"""FortiGuard connection, signature updates and firmware: the services a license pays for.

On the free evaluation license FortiGuard is unreachable by design, so these tools report that
plainly. On a licensed unit they show whether updates are actually arriving. Licensed-unit
responses are modelled on FortiOS 7.6's schema and not yet verified on a licensed device.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from ..client import FortiGateAPIError, FortiGateClient
from ._common import BOOL, results, schema, vdom_param
from ._license import features_report, license_info

STALE_DAYS = 7
FORTIGUARD_SETTINGS = (
    "protocol", "port", "fortiguard-anycast", "update-server-location", "auto-join-forticloud",
    "auto-firmware-upgrade", "auto-firmware-upgrade-day", "auto-firmware-upgrade-delay",
    "auto-firmware-upgrade-start-hour", "auto-firmware-upgrade-end-hour",
)

TOOLS = [
    {
        "name": "get_fortiguard_status",
        "description": (
            "Whether FortiGuard updates are actually reaching this FortiGate: connection state, each "
            "FortiGuard server's reachability and packet loss, the update schedule, which services are "
            "licensed, and how old each signature database is. Adds findings for failing servers, "
            "stale signatures on licensed services and a disabled update schedule. On the free "
            "evaluation license it says that FortiGuard is unavailable by design."
        ),
        "inputSchema": schema({}),
    },
    {
        "name": "update_fortiguard",
        "description": (
            "Ask the FortiGate to contact FortiGuard now and refresh its entitlements and signature "
            "packages (the GUI's 'Check update now'). Needs a FortiGuard license. With dry_run (the "
            "default) it only reports what would happen and the current signature ages."
        ),
        "inputSchema": schema({"dry_run": BOOL("Only report (default true)")}),
    },
    {
        "name": "get_firmware_status",
        "description": (
            "Running firmware (version, build, maturity, release notes), newer images FortiGuard "
            "offers, the supported upgrade path, and the automatic firmware upgrade settings. Images "
            "and upgrade paths come from FortiGuard, so the evaluation license lists none; check "
            "https://www.fortiguard.com/psirt for the running release by hand there."
        ),
        "inputSchema": schema({}),
    },
]


async def _try(coro: Any) -> tuple[Any, str | None]:
    try:
        return await coro, None
    except FortiGateAPIError as e:
        return None, str(e)


def _servers(info: Any) -> list[dict[str, Any]]:
    out = []
    for addr, s in (info.items() if isinstance(info, dict) else []):
        if not isinstance(s, dict):
            continue
        status = s.get("status") or {}
        packets = s.get("packets") or 0
        lost = s.get("current_lost") or 0
        out.append({
            "server": addr,
            "failing": bool(status.get("fail")),
            "rtt_ms": s.get("rtt"),
            "packet_loss_pct": round(100 * lost / packets) if packets else None,
        })
    return out


async def fortiguard_status(client: FortiGateClient, v: dict[str, Any]) -> dict[str, Any]:
    info = await license_info(client, v, refresh=True)
    report = features_report(info)
    (servers, servers_err), (schedule, _), (settings, _) = await asyncio.gather(
        _try(client.get("/api/v2/monitor/system/fortiguard/server-info", v)),
        _try(client.get("/api/v2/cmdb/system.autoupdate/schedule", v)),
        _try(client.get("/api/v2/cmdb/system/fortiguard", v)),
    )
    server_list = _servers(results(servers))
    schedule = results(schedule) if schedule else {}
    settings = results(settings) if settings else {}

    findings: list[dict[str, str]] = []

    def add(severity: str, check: str, detail: str, fix: str) -> None:
        findings.append({"severity": severity, "check": check, "detail": detail, "fix": fix})

    licensed = set(report["licensed"]) - {"fortiguard", "forticare"}
    if not info.is_eval:
        failing = [s["server"] for s in server_list if s["failing"]]
        if failing:
            add("critical" if len(failing) == len(server_list) else "warn", "fortiguard_servers",
                f"FortiGuard server(s) failing: {', '.join(failing)}",
                "Check DNS, the default route and that outbound HTTPS/UDP 53/8888 reaches FortiGuard; "
                "update_fortiguard then retries")
        if info.fortiguard_connected is False and licensed:
            add("critical", "fortiguard_connection", "Licensed services, but not connected to FortiGuard",
                "Fix connectivity, then run update_fortiguard")
        for name, db in report["signature_databases"].items():
            age = db.get("age_days")
            if name in licensed and age is not None and age > STALE_DAYS:
                add("warn", "stale_signatures", f"{name} signatures are {age} days old although licensed",
                    "Run update_fortiguard and check the update schedule")
        if isinstance(schedule, dict) and schedule.get("status") == "disable" and licensed:
            add("warn", "update_schedule", "Scheduled FortiGuard updates are disabled",
                "set status enable under config system autoupdate schedule (set_config "
                "endpoint=system.autoupdate/schedule)")

    out: dict[str, Any] = {
        "edition": report["edition"],
        "fortiguard_connected": info.fortiguard_connected,
        "servers": server_list if server_list else (servers_err or []),
        "update_schedule": schedule,
        "settings": {k: settings.get(k) for k in FORTIGUARD_SETTINGS if isinstance(settings, dict) and k in settings},
        "licensed": report["licensed"],
        "signature_databases": report["signature_databases"],
        "findings": findings,
    }
    if info.is_eval:
        out["note"] = ("The free evaluation license has no FortiGuard entitlement, so servers show as failing "
                       "and signatures stay at their factory versions. That is expected, not a fault.")
    return out


def _version_key(img: dict[str, Any]) -> tuple[int, int, int, int]:
    return tuple(int(img.get(k) or 0) for k in ("major", "minor", "patch", "build"))  # type: ignore[return-value]


async def firmware_status(client: FortiGateClient, v: dict[str, Any]) -> dict[str, Any]:
    info = await license_info(client, v)
    (fw, fw_err), (paths, paths_err), (settings, _) = await asyncio.gather(
        _try(client.get("/api/v2/monitor/system/firmware", v)),
        _try(client.get("/api/v2/monitor/system/firmware/upgrade-paths", v)),
        _try(client.get("/api/v2/cmdb/system/fortiguard", v)),
    )
    fw = results(fw) if fw else {}
    fw = fw if isinstance(fw, dict) else {}
    current = fw.get("current") or {}
    available = [i for i in (fw.get("available") or []) if isinstance(i, dict)]
    newer = sorted((i for i in available if _version_key(i) > _version_key(current)), key=_version_key)
    settings = results(settings) if settings else {}

    def brief(img: dict[str, Any]) -> dict[str, Any]:
        return {k: img.get(k) for k in ("version", "build", "maturity", "release-type", "notes", "id") if k in img}

    out: dict[str, Any] = {
        "current": brief(current) if current else fw_err,
        "newer_images": [brief(i) for i in newer],
        "upgrade_path": results(paths) if paths else None,
        "auto_firmware_upgrade": {k: settings.get(k) for k in FORTIGUARD_SETTINGS
                                  if k.startswith("auto-firmware") and isinstance(settings, dict) and k in settings},
        "psirt": "https://www.fortiguard.com/psirt",
    }
    if newer:
        out["latest"] = brief(newer[-1])
    if paths_err:
        out["upgrade_path_error"] = ("FortiOS couldn't compute an upgrade path (it needs FortiGuard): "
                                     f"{paths_err}")
    if info.is_eval:
        out["note"] = ("The evaluation license can't download images from FortiGuard, so no newer images or "
                       "upgrade paths are listed. Upload images by hand and check the PSIRT page for the "
                       "running release.")
    return out


async def handle(name: str, args: dict[str, Any], client: FortiGateClient) -> Any:
    v = vdom_param(args)

    if name == "get_fortiguard_status":
        return await fortiguard_status(client, v)

    elif name == "update_fortiguard":
        info = await license_info(client, v, refresh=True)
        info.require("fortiguard", "Updating from FortiGuard")
        ages = {k: d.get("age_days") for k, d in features_report(info)["signature_databases"].items()}
        if args.get("dry_run", True) is not False:
            return {"dry_run": True, "request": "POST /api/v2/monitor/system/fortiguard/update",
                    "signature_age_days": ages,
                    "note": "Set dry_run=false to contact FortiGuard now. Updates download in the background; "
                            "run get_fortiguard_status after a minute or two."}
        await client.post("/api/v2/monitor/system/fortiguard/update", {}, v)
        return {"status": "requested", "requested_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "signature_age_days_before": ages,
                "note": "Run get_fortiguard_status after a minute or two to see the new versions."}

    elif name == "get_firmware_status":
        return await firmware_status(client, v)

    raise ValueError(f"Unknown tool: {name}")
