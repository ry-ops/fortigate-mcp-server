"""HA cluster status, FortiTokens, and two-factor authentication for administrators.

Registered by system.py. The MFA write goes through config.set_config, so it is validated against
the FortiGate's schema and defaults to a dry run. Licensed-unit behaviour (tokens, HA clusters) is
modelled on FortiOS 7.6's schema and not yet verified on a licensed device.
"""

from __future__ import annotations

import asyncio
from typing import Any

from ..client import FortiGateAPIError, FortiGateClient
from ._common import BOOL, STR, results, schema, vdom_param
from ._license import license_info

HA_FIELDS = ("mode", "group-name", "group-id", "priority", "override", "hbdev", "session-pickup",
             "encryption", "authentication", "monitor", "ha-mgmt-status")
MFA_METHODS = ("fortitoken", "email", "sms", "disable")

TOOLS = [
    {
        "name": "get_ha_status",
        "description": (
            "High availability: the mode (standalone, active-passive, active-active), group, "
            "heartbeat interfaces and monitored interfaces, each cluster member with its role, "
            "priority and uptime, and whether members' configurations are in sync. Flags "
            "out-of-sync members, unencrypted or unauthenticated heartbeats, a single heartbeat "
            "interface and no session pickup."
        ),
        "inputSchema": schema({}),
    },
    {
        "name": "list_fortitokens",
        "description": (
            "FortiTokens on the FortiGate (serial, status, license) and which administrators use "
            "two-factor authentication, by which method and token. Tokens are activated through "
            "FortiGuard, so the evaluation license has none."
        ),
        "inputSchema": schema({}),
    },
    {
        "name": "set_admin_mfa",
        "description": (
            "Turn on two-factor authentication for an administrator: fortitoken (needs an "
            "activated token serial), email (needs email_to and a working email server) or sms "
            "(needs sms_phone and SMS service); or disable it. Checks the prerequisites first. "
            "dry_run (the default) shows the change. Test a login in a private window before "
            "closing your current session."
        ),
        "inputSchema": schema(
            {
                "admin": STR("Administrator name"),
                "method": STR("fortitoken, email, sms or disable"),
                "fortitoken": STR("Token serial for method fortitoken"),
                "email_to": STR("Address for method email"),
                "sms_phone": STR("Phone number for method sms"),
                "dry_run": BOOL("Only validate and show the change (default true)"),
            },
            ["admin", "method"],
        ),
    },
]


async def _get(client: FortiGateClient, path: str, v: dict[str, Any], params: dict[str, Any] | None = None) -> Any:
    try:
        return results(await client.get(path, {**v, **(params or {})}))
    except FortiGateAPIError:
        return None


async def ha_status(client: FortiGateClient, v: dict[str, Any]) -> dict[str, Any]:
    ha, peers, stats, checksums = await asyncio.gather(
        _get(client, "/api/v2/cmdb/system/ha", v, {"format": "|".join(HA_FIELDS)}),
        _get(client, "/api/v2/monitor/system/ha-peer", v),
        _get(client, "/api/v2/monitor/system/ha-statistics", v),
        _get(client, "/api/v2/monitor/system/ha-checksums", v))
    ha = ha if isinstance(ha, dict) else {}
    mode = ha.get("mode", "standalone")
    out: dict[str, Any] = {"mode": mode, "settings": {k: ha.get(k) for k in HA_FIELDS if k in ha}}
    if mode == "standalone":
        out["note"] = "This FortiGate isn't in an HA cluster."
        return out

    members = []
    for p in peers if isinstance(peers, list) else []:
        members.append({k: p.get(k) for k in ("serial_no", "hostname", "priority", "vcluster_id", "is_manage_primary",
                                               "uptime") if k in p})
    out["members"] = members
    if isinstance(stats, list):
        out["statistics"] = stats

    findings: list[dict[str, str]] = []

    def add(severity: str, check: str, detail: str, fix: str) -> None:
        findings.append({"severity": severity, "check": check, "detail": detail, "fix": fix})

    # Each member reports checksums per scope (global, root...); members are in sync when they match.
    if isinstance(checksums, list) and len(checksums) > 1:
        def sums(m: dict[str, Any]) -> Any:
            return m.get("checksum") or {k: val for k, val in m.items() if k not in ("serial_no", "is_manage_primary")}
        first = sums(checksums[0])
        if any(sums(m) != first for m in checksums[1:]):
            add("warn", "out_of_sync", "Cluster members' configuration checksums differ",
                "Check get_monitor endpoint=system/ha-checksums; resync from the primary")
    if ha.get("encryption") == "disable":
        add("warn", "hb_encryption", "Heartbeat traffic isn't encrypted", "set encryption enable under config system ha")
    if ha.get("authentication") == "disable":
        add("warn", "hb_authentication", "Heartbeat traffic isn't authenticated",
            "set authentication enable under config system ha")
    if len(str(ha.get("hbdev") or "").split()) <= 2:  # "port3 50" is one device with its priority
        add("info", "single_heartbeat", "Only one heartbeat interface; losing it splits the cluster",
            "Add a second hbdev")
    if ha.get("session-pickup") == "disable":
        add("info", "session_pickup", "Sessions aren't synchronised, so connections drop on failover",
            "set session-pickup enable if failover should be seamless")
    out["findings"] = findings
    return out


async def fortitokens(client: FortiGateClient, v: dict[str, Any]) -> dict[str, Any]:
    info, tokens, cfg, admins = await asyncio.gather(
        license_info(client, v),
        _get(client, "/api/v2/monitor/user/fortitoken", v),
        _get(client, "/api/v2/cmdb/user/fortitoken", v),
        _get(client, "/api/v2/cmdb/system/admin", v, {"format": "name|two-factor|fortitoken|email-to|sms-phone"}))
    token_list = []
    for t in cfg if isinstance(cfg, list) else []:
        serial = t.get("serial-number")
        live = tokens.get(serial, {}) if isinstance(tokens, dict) else {}
        token_list.append({"serial": serial, "status": live.get("status") or t.get("status"),
                           "license": t.get("license"), "comments": t.get("comments", "")})
    admin_list = []
    for a in admins if isinstance(admins, list) else []:
        method = a.get("two-factor", "disable")
        entry: dict[str, Any] = {"admin": a.get("name"), "two_factor": method}
        if method == "fortitoken":
            entry["token"] = a.get("fortitoken")
        elif method == "email":
            entry["email_to"] = a.get("email-to")
        admin_list.append(entry)
    out: dict[str, Any] = {"tokens": token_list, "admins": admin_list,
                           "admins_without_mfa": [a["admin"] for a in admin_list if a["two_factor"] == "disable"]}
    if info.is_eval:
        out["note"] = ("Tokens are activated through FortiGuard, which the evaluation license can't reach. "
                       "Email two-factor works if the FortiGate can send mail; otherwise rely on trusted hosts "
                       "and a local-in allowlist.")
    return out


async def set_admin_mfa(client: FortiGateClient, args: dict[str, Any]) -> dict[str, Any]:
    from . import config  # imported here to avoid a cycle with the module registry

    v = vdom_param(args)
    method = args["method"]
    if method not in MFA_METHODS:
        raise ValueError(f"method must be one of {', '.join(MFA_METHODS)}")
    fields: dict[str, Any] = {"two-factor": method}
    checks: list[str] = []
    if method == "fortitoken":
        serial = args.get("fortitoken")
        if not serial:
            raise ValueError("Pass fortitoken: the serial of an activated token (list_fortitokens)")
        tokens = await _get(client, "/api/v2/monitor/user/fortitoken", v)
        status = (tokens or {}).get(serial, {}).get("status") if isinstance(tokens, dict) else None
        if status != "active":
            raise ValueError(f"Token {serial} isn't active (status: {status or 'not found'}); activate it first")
        fields["fortitoken"] = serial
        checks.append(f"token {serial} is active")
    elif method == "email":
        if not args.get("email_to"):
            raise ValueError("Pass email_to: where the FortiGate sends the login code")
        mail = await _get(client, "/api/v2/cmdb/system/email-server", v, {"format": "server|port|security"})
        server = (mail or {}).get("server") if isinstance(mail, dict) else None
        if not server:
            raise ValueError("No email server is configured (config system email-server), so codes can't be sent")
        fields["email-to"] = args["email_to"]
        checks.append(f"codes are sent through {server}; make sure that relay accepts mail from this FortiGate")
    elif method == "sms":
        if not args.get("sms_phone"):
            raise ValueError("Pass sms_phone")
        fields["sms-phone"] = args["sms_phone"]
        fields["sms-server"] = "fortiguard"
        checks.append("SMS through FortiGuard needs SMS credits on the FortiGate's FortiCare account")
    result = await config.set_config(client, {"endpoint": "system/admin", "mkey": args["admin"], "fields": fields,
                                              "dry_run": args.get("dry_run", True), "vdom": args.get("vdom")})
    if checks:
        result["checks"] = checks
    if method != "disable":
        result["before_you_log_out"] = ("Log in as this admin in a private window and complete the second factor "
                                        "before closing your current session.")
    return result


async def handle(name: str, args: dict[str, Any], client: FortiGateClient) -> Any:
    v = vdom_param(args)
    if name == "get_ha_status":
        return await ha_status(client, v)
    if name == "list_fortitokens":
        return await fortitokens(client, v)
    if name == "set_admin_mfa":
        return await set_admin_mfa(client, args)
    raise ValueError(f"Unknown tool: {name}")
