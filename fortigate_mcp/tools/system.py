"""System tools: status, license, resources, interfaces, admin sessions, config backup."""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any

from ..client import FortiGateClient
from ._common import (
    BOOL,
    EXTRA,
    LIST_PROPS,
    STR,
    STR_LIST,
    body,
    list_params,
    mkey,
    one,
    results,
    schema,
    subnet,
    vdom_param,
    write_result,
)

TOOLS = [
    {
        "name": "get_system_status",
        "description": "FortiGate model, serial, firmware version/build, hostname and uptime.",
        "inputSchema": schema({}),
    },
    {
        "name": "get_license_status",
        "description": (
            "License and FortiGuard contract status. By default returns only the VM license, "
            "FortiCare and FortiGuard sections; set all=true for every entitlement. An unlicensed "
            "FortiGate-VM reports vm.status=vm_invalid and refuses most other API calls with 401."
        ),
        "inputSchema": schema({"all": BOOL("Return every entitlement (default false)")}),
    },
    {
        "name": "get_resource_usage",
        "description": "Current CPU, memory, disk and session usage.",
        "inputSchema": schema({}),
    },
    {
        "name": "list_interfaces",
        "description": "List interface configuration (IP, mode, role, alias, allowaccess).",
        "inputSchema": schema({**LIST_PROPS}),
    },
    {
        "name": "get_interface",
        "description": "Get one interface's full configuration.",
        "inputSchema": schema({"name": STR("Interface name, e.g. port1")}, ["name"]),
    },
    {
        "name": "get_interface_status",
        "description": "Live interface state: link, speed, IP and traffic counters.",
        "inputSchema": schema({"interface": STR("Limit to one interface (optional)")}),
    },
    {
        "name": "update_interface",
        "description": (
            "Update an interface. Changing the interface this server connects through (its IP, "
            "mode or allowaccess) can cut off API access, so double-check those changes."
        ),
        "inputSchema": schema(
            {
                "name": STR("Interface name, e.g. port2"),
                "alias": STR("Alias"),
                "mode": STR("Addressing mode: static, dhcp or pppoe"),
                "ip": STR("Address in CIDR form (10.0.0.1/24) or 'ip mask'"),
                "role": STR("Role: lan, wan, dmz or undefined"),
                "allowaccess": STR_LIST("Management access, e.g. [ping, https, ssh]"),
                "status": STR("up or down"),
                "description": STR("Description"),
                "extra": EXTRA,
            },
            ["name"],
        ),
    },
    {
        "name": "list_admin_sessions",
        "description": "Administrators currently logged in (GUI, SSH, API) and where from.",
        "inputSchema": schema({}),
    },
    {
        "name": "backup_config",
        "description": (
            "Back up the full running configuration (FortiOS CLI text) to a local file and return "
            "its path and size. Allowed in read-only mode. Configs are hundreds of KB, so the text "
            "itself is not returned."
        ),
        "inputSchema": schema(
            {"output_path": STR("File to write (default ./fortigate-<hostname>-<timestamp>.conf)")}
        ),
    },
    {
        "name": "forticonverter_setup_prompt",
        "description": (
            "Show or hide the 'Migrate Config with FortiConverter' step of the GUI's FortiGate Setup "
            "popup. Without hide, only reports the current state. FortiGate-VM evaluation licenses are "
            "not eligible for FortiConverter, so that step never completes and the popup reappears at "
            "every login until it is hidden. There is no CLI equivalent."
        ),
        "inputSchema": schema({"hide": BOOL("true hides the step, false shows it again; omit to read")}),
    },
]

FORTICONVERTER_PROMPT = "/api/v2/monitor/forticonverter/show-in-startup"


async def handle(name: str, args: dict[str, Any], client: FortiGateClient) -> Any:
    v = vdom_param(args)

    if name == "get_system_status":
        resp = await client.get("/api/v2/monitor/system/status", v)
        # Serial, version and build sit beside "results", not inside it.
        out: dict[str, Any] = {}
        if isinstance(resp, dict):
            out = {k: resp[k] for k in ("serial", "version", "build") if k in resp}
        res = results(resp)
        out.update(res if isinstance(res, dict) else {"results": res})
        return out

    elif name == "get_license_status":
        lic = results(await client.get("/api/v2/monitor/license/status", v))
        if args.get("all") or not isinstance(lic, dict):
            return lic
        return {k: lic.get(k) for k in ("vm", "forticare", "fortiguard", "forticloud")}

    elif name == "get_resource_usage":
        usage = results(await client.get("/api/v2/monitor/system/resource/usage", {**v, "interval": "1-min"}))
        if not isinstance(usage, dict):
            return usage
        # Each metric carries a history series; keep only the current value.
        return {k: (val[0].get("current") if isinstance(val, list) and val else val) for k, val in usage.items()}

    elif name == "list_interfaces":
        return results(await client.get("/api/v2/cmdb/system/interface", list_params(args)))

    elif name == "get_interface":
        return one(await client.get(f"/api/v2/cmdb/system/interface/{mkey(args['name'])}", v))

    elif name == "get_interface_status":
        params = {**v, "interface_name": args.get("interface")}
        return results(await client.get("/api/v2/monitor/system/interface", params))

    elif name == "update_interface":
        data = body(
            args,
            {"alias": "alias", "mode": "mode", "role": "role", "status": "status",
             "description": "description"},
        )
        if args.get("ip"):
            data["ip"] = subnet(args["ip"])
        if args.get("allowaccess") is not None:
            data["allowaccess"] = " ".join(args["allowaccess"])
        path = f"/api/v2/cmdb/system/interface/{mkey(args['name'])}"
        return write_result(await client.put(path, data, v))

    elif name == "list_admin_sessions":
        return results(await client.get("/api/v2/monitor/system/current-admins", v))

    elif name == "backup_config":
        # FortiOS 7.4+ serves backups via POST only; it changes nothing on the device.
        text = await client.request(
            "POST", "/api/v2/monitor/system/config/backup", v,
            {"destination": "file", "scope": "global"}, read_only_safe=True,
        )
        if not isinstance(text, str) or not text.startswith("#config-version"):
            raise RuntimeError(f"Unexpected backup response: {str(text)[:200]}")
        header = text.splitlines()[0]
        m = re.search(r'^\s*set hostname "([^"]+)"', text, re.M)
        hostname = m.group(1) if m else "fortigate"
        path = Path(args.get("output_path") or f"fortigate-{hostname}-{time.strftime('%Y%m%d-%H%M%S')}.conf")
        path.write_text(text)
        return {"path": str(path.resolve()), "bytes": len(text.encode()), "config_version": header}

    elif name == "forticonverter_setup_prompt":
        if args.get("hide") is not None:
            # Undocumented endpoint used by the GUI (setPromptVisibility); the body is {"hide": bool}.
            await client.post(f"{FORTICONVERTER_PROMPT}/set", {"hide": bool(args["hide"])}, v)
        return results(await client.get(FORTICONVERTER_PROMPT, v))

    raise ValueError(f"Unknown tool: {name}")
