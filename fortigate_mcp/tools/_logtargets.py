"""Where the FortiGate's logs go: syslog servers, FortiAnalyzer, FortiGuard Cloud, disk and memory.

Registered by logs.py. Writes go through config.set_config, so they are validated against the
FortiGate's schema and default to a dry run.
"""

from __future__ import annotations

import asyncio
from typing import Any

from ..client import FortiGateAPIError, FortiGateClient
from ._common import BOOL, INT, STR, results, schema, vdom_param
from ._license import license_info

SYSLOG_SLOTS = ("log.syslogd", "log.syslogd2", "log.syslogd3", "log.syslogd4")
FAZ_SLOTS = ("log.fortianalyzer", "log.fortianalyzer2", "log.fortianalyzer3")

TOOLS = [
    {
        "name": "get_log_targets",
        "description": (
            "Where logs go: each syslog server (up to 4), FortiAnalyzer (up to 3), FortiGuard Cloud, "
            "local disk and memory, with transport and encryption. Flags logs that only live in "
            "memory (lost on reboot), syslog sent as cleartext UDP, and FortiAnalyzer without "
            "certificate verification."
        ),
        "inputSchema": schema({}),
    },
    {
        "name": "set_syslog_target",
        "description": (
            "Send logs to a syslog server: sets server, port and transport on one of the four syslog "
            "slots and enables it. mode is udp (default), reliable (TCP) or legacy-reliable; with "
            "reliable, enc_algorithm (high, high-medium, low) adds TLS. Validated against the "
            "FortiGate's schema; dry_run (the default) shows the change without sending it."
        ),
        "inputSchema": schema(
            {
                "server": STR("Collector IP or FQDN"),
                "port": INT("Port (default 514; 6514 is usual for TLS)"),
                "mode": STR("udp, reliable or legacy-reliable (default udp)"),
                "enc_algorithm": STR("TLS for reliable mode: high, high-medium, low or disable"),
                "slot": INT("Syslog slot 1-4 (default 1)"),
                "disable": BOOL("Turn the slot off instead (server ignored)"),
                "dry_run": BOOL("Only validate and show the change (default true)"),
            },
        ),
    },
]


async def _get(client: FortiGateClient, path: str, v: dict[str, Any]) -> Any:
    try:
        return results(await client.get(path, v))
    except FortiGateAPIError:
        return None


async def log_targets(client: FortiGateClient, v: dict[str, Any]) -> dict[str, Any]:
    paths = [f"/api/v2/cmdb/{s}/setting" for s in SYSLOG_SLOTS + FAZ_SLOTS] + [
        "/api/v2/cmdb/log.fortiguard/setting", "/api/v2/cmdb/log.disk/setting",
        "/api/v2/cmdb/log.memory/setting", "/api/v2/monitor/system/status"]
    info, *rows = await asyncio.gather(license_info(client, v), *(_get(client, p, v) for p in paths))
    syslogs, fazs = rows[:4], rows[4:7]
    fgd, disk, memory, status = rows[7:]
    findings: list[dict[str, str]] = []

    def add(severity: str, check: str, obj: str, detail: str, fix: str) -> None:
        findings.append({"severity": severity, "check": check, "object": obj, "detail": detail, "fix": fix})

    syslog_out = []
    for slot, s in enumerate(syslogs, 1):
        if not isinstance(s, dict) or s.get("status") != "enable":
            continue
        entry = {k: s.get(k) for k in ("server", "port", "mode", "enc-algorithm", "format", "facility")}
        syslog_out.append({"slot": slot, **entry})
        if s.get("mode") == "udp" or s.get("enc-algorithm") in (None, "disable"):
            add("info", "syslog_cleartext", f"syslog slot {slot}",
                f"Logs to {s.get('server')} travel unencrypted ({s.get('mode')})",
                "Use mode reliable with enc_algorithm high if the collector supports TLS (set_syslog_target)")
    faz_out = []
    for slot, f in enumerate(fazs, 1):
        if not isinstance(f, dict) or f.get("status") != "enable":
            continue
        faz_out.append({"slot": slot, **{k: f.get(k) for k in ("server", "reliable", "enc-algorithm",
                                                                   "certificate-verification", "upload-option")}})
        if f.get("certificate-verification") == "disable":
            add("warn", "faz_cert_verification", f"FortiAnalyzer {slot}",
                "The FortiAnalyzer's certificate isn't verified, so logs could go to an impostor",
                "set certificate-verification enable with the FortiAnalyzer's serial")
    cloud = isinstance(fgd, dict) and fgd.get("status") == "enable"
    disk_on = isinstance(disk, dict) and disk.get("status") == "enable"
    has_disk = isinstance(status, dict) and status.get("log_disk_status") not in (None, "not_available")
    if not (syslog_out or faz_out or cloud):
        where = "disk only" if disk_on else "memory only, and lost on reboot"
        add("warn", "no_remote_logging", "log targets", f"No remote log target; logs are kept in {where}",
            "Send them to a syslog collector with set_syslog_target")
    if cloud and info.is_eval:
        add("info", "cloud_unlicensed", "FortiGuard Cloud", "FortiGuard Cloud logging is enabled but the "
            "evaluation license doesn't include it", "Disable it and use syslog")
    return {
        "syslog": syslog_out,
        "fortianalyzer": faz_out,
        "fortiguard_cloud": cloud,
        "disk": {"enabled": disk_on, "log_disk_present": has_disk},
        "memory": isinstance(memory, dict) and memory.get("status") == "enable",
        "findings": findings,
    }


async def handle(name: str, args: dict[str, Any], client: FortiGateClient) -> Any:
    v = vdom_param(args)
    if name == "get_log_targets":
        return await log_targets(client, v)
    if name == "set_syslog_target":
        from . import config  # imported here to avoid a cycle with the module registry

        slot = int(args.get("slot") or 1)
        if not 1 <= slot <= 4:
            raise ValueError("slot must be 1-4")
        if args.get("disable"):
            fields: dict[str, Any] = {"status": "disable"}
        else:
            if not args.get("server"):
                raise ValueError("Pass server (the collector's IP or FQDN)")
            fields = {"status": "enable", "server": args["server"], "port": args.get("port") or 514,
                      "mode": args.get("mode") or "udp"}
            if args.get("enc_algorithm"):
                if fields["mode"] == "udp":
                    raise ValueError("enc_algorithm needs mode reliable (TLS runs over TCP)")
                fields["enc-algorithm"] = args["enc_algorithm"]
        return await config.set_config(client, {
            "endpoint": f"{SYSLOG_SLOTS[slot - 1]}/setting", "fields": fields,
            "dry_run": args.get("dry_run", True), "vdom": args.get("vdom")})
    raise ValueError(f"Unknown tool: {name}")
