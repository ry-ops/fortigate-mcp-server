"""System tools: status, license, resources, interfaces, admin access, config backup."""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import time
from pathlib import Path
from typing import Any

from ..client import FortiGateAPIError, FortiGateClient
from . import _access as access
from ._capacity import capacity
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
from ._hardening import EVAL_NOT_APPLICABLE, _has_admin_deny, annotate, fix_plan, hardening_checks
from ._license import features_report, license_info

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
        "name": "get_license_limits",
        "description": (
            "How much of the license's object limits is used. The free FortiGate-VM evaluation "
            "license allows 1 vCPU, 2 GB RAM and at most 3 interfaces, 3 firewall policies and 3 "
            "static routes; this lists what counts against each so you can plan before hitting one."
        ),
        "inputSchema": schema({}),
    },
    {
        "name": "get_license_features",
        "description": (
            "What this FortiGate is licensed for: free evaluation VM, licensed VM or hardware; whether "
            "it reaches FortiGuard; which FortiGuard services (IPS, antivirus, web filter, application "
            "control, Internet Service Database, FortiCloud logging...) are licensed, not licensed or "
            "expiring within 30 days; and the version and age of each signature database. Tools that "
            "need a FortiGuard service check this and say so when it's missing."
        ),
        "inputSchema": schema({}),
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
        "name": "audit_admin_access",
        "description": (
            "Read-only audit of how the FortiGate can be administered: admins without trusted hosts "
            "or MFA, the default 'admin' account, API keys, HTTPS/SSH/HTTP/telnet admin access on WAN "
            "interfaces, local-in policies, and admin passwords still stored as legacy SHA-256 instead "
            "of PBKDF2. Returns findings graded critical/warn/info, each with a suggested fix. The "
            "hash check reads a config backup, which the FortiGate logs as a config download; set "
            "check_hashes=false to skip it."
        ),
        "inputSchema": schema(
            {"check_hashes": BOOL("Check stored password hashes via a config backup (default true)")}
        ),
    },
    {
        "name": "audit_hardening",
        "description": (
            "Read-only hardening audit: everything audit_admin_access checks, plus admin access on "
            "LAN interfaces, local-in coverage, telnet, FortiCloud SSO, crypto and TLS settings, SSL "
            "VPN, logging (implicit deny, local-in denies, remote targets, cleartext syslog), password "
            "policy, NTP, FortiGuard updates and stale signatures, whether accept policies are protected "
            "by security profiles, and HA heartbeat hardening. "
            "Each finding carries the order to fix it in and whether the fix can cut off admin access, "
            "and fix_plan lists them in that order. On the evaluation license it lists the FortiGuard "
            "features that don't apply and what to rely on instead. check_hashes reads a config "
            "backup, as in audit_admin_access."
        ),
        "inputSchema": schema(
            {"check_hashes": BOOL("Check stored password hashes via a config backup (default true)")}
        ),
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
    {
        "name": "activate_vm_eval_license",
        "description": (
            "Activate the free permanent evaluation license on an unlicensed FortiGate-VM by logging "
            "in to FortiCloud from the FortiGate (the same call the GUI makes). The FortiCloud "
            "account comes from the FORTICLOUD_ACCOUNT and FORTICLOUD_PASSWORD environment variables, "
            "never from tool arguments. The FortiGate reboots to apply it. Unlicensed VMs refuse "
            "most API calls, so use session auth (FORTIGATE_USERNAME/PASSWORD) on a fresh VM. "
            "FortiCare error 10 means wrong credentials, an IAM sub-user, or 2FA on the account."
        ),
        "inputSchema": schema(
            {
                "confirm": BOOL("Must be true: the FortiGate reboots"),
                "is_government": BOOL("Government account (default false)"),
            },
            ["confirm"],
        ),
    },
]
TOOLS += access.TOOLS

FORTICONVERTER_PROMPT = "/api/v2/monitor/forticonverter/show-in-startup"

# First releases that store admin passwords with PBKDF2 instead of SHA-256 ("PB2" vs "SH2").
PBKDF2_SINCE = {(7, 2): (7, 2, 11), (7, 4): (7, 4, 8), (7, 6): (7, 6, 1)}
ADMIN_ACCESS = ("https", "ssh", "http", "telnet")
OPEN_TRUSTHOSTS = {"0.0.0.0 0.0.0.0", "::/0"}
SEVERITY = {"critical": 0, "warn": 1, "info": 2}


async def _backup_text(client: FortiGateClient, v: dict[str, Any]) -> str:
    # FortiOS 7.4+ serves backups via POST only; it changes nothing on the device.
    text = await client.request(
        "POST", "/api/v2/monitor/system/config/backup", v,
        {"destination": "file", "scope": "global"}, read_only_safe=True,
    )
    if not isinstance(text, str) or not text.startswith("#config-version"):
        raise RuntimeError(f"Unexpected backup response: {str(text)[:200]}")
    return text


def _version(text: str) -> tuple[int, ...]:
    return tuple(int(n) for n in re.findall(r"\d+", text or "")[:3])


def _supports_pbkdf2(version: tuple[int, ...]) -> bool:
    if len(version) < 3:
        return False
    since = PBKDF2_SINCE.get(version[:2])
    return version >= since if since else version[:2] > (7, 6)


def _admin_hashes(text: str) -> dict[str, dict[str, str]]:
    """Hash scheme prefix (SH2, PB2...) of each admin's password and old-password; never the hash."""
    block = re.search(r"^config system admin\n(.*?)^end$", text, re.M | re.S)
    out: dict[str, dict[str, str]] = {}
    admins = block.group(1) if block else ""
    for m in re.finditer(r'^    edit "([^"]+)"\n(.*?)^    next$', admins, re.M | re.S):
        out[m.group(1)] = {
            key: h.group(1)
            for key in ("password", "old-password")
            if (h := re.search(rf"^        set {key} ENC (\w{{3}})", m.group(2), re.M))
        }
    return out


def _trusthosts(entry: dict[str, Any]) -> list[str]:
    hosts = [v for k, v in entry.items() if re.fullmatch(r"(ip6-)?trusthost\d+", k) and v]
    for th in entry.get("trusthost") or []:  # api-user lists them as a table
        hosts.append(th.get("ipv4-trusthost") or th.get("ipv6-trusthost") or "")
    return [h for h in hosts if h]


def _is_private(cidr: str) -> bool:
    try:
        return ipaddress.ip_address(cidr.split()[0]).is_private
    except ValueError:
        return False


async def audit_admin_access(
    client: FortiGateClient, v: dict[str, Any], check_hashes: bool = True
) -> dict[str, Any]:
    findings: list[dict[str, str]] = []

    def add(severity: str, check: str, obj: str, detail: str, fix: str) -> None:
        findings.append({"severity": severity, "check": check, "object": obj, "detail": detail, "fix": fix})

    async def read(path: str) -> Any:
        try:
            return results(await client.get(path, v))
        except FortiGateAPIError as e:
            add("info", "not_checked", path, f"Could not read: {e}",
                "Use a token with read access to this path")
            return None

    status, admins, api_users, interfaces, local_in, pw_policy = await asyncio.gather(
        client.get("/api/v2/monitor/system/status", v),
        read("/api/v2/cmdb/system/admin"),
        read("/api/v2/cmdb/system/api-user"),
        read("/api/v2/cmdb/system/interface"),
        read("/api/v2/cmdb/firewall/local-in-policy"),
        read("/api/v2/cmdb/system/password-policy"),
    )
    firmware = status.get("version", "") if isinstance(status, dict) else ""
    version = _version(firmware)
    admins, api_users = admins or [], api_users or []

    open_admins = [a["name"] for a in admins if all(h in OPEN_TRUSTHOSTS for h in _trusthosts(a))]
    for a in admins:
        name = a["name"]
        if name in open_admins:
            add("warn", "admin_trusthosts", name, "Accepts logins from any address (no trusted hosts)",
                "Set trusthost1.. to the management subnets")
        if a.get("two-factor", "disable") == "disable" and a.get("remote-auth") != "enable":
            add("warn", "admin_mfa", name, "No two-factor authentication",
                "Enable two-factor (FortiToken, email or SMS)")
        if name == "admin":
            add("info", "default_admin", name,
                "Default account name, first in every password-spraying list",
                "Create named admins and remove or disable 'admin'")
    for u in api_users:
        if not _trusthosts(u):
            add("critical", "api_user_trusthosts", u["name"], "API key usable from any address",
                "Add trusted hosts to the API user")
        if u.get("accprofile") == "super_admin":
            add("info", "api_user_profile", u["name"], "API key has super_admin rights",
                "Use a narrower admin profile if full rights are not needed")

    for i in interfaces or []:
        exposed = [s for s in (i.get("allowaccess") or "").split() if s in ADMIN_ACCESS]
        if i.get("role") == "wan" and exposed:
            where = f"{i['name']} ({i.get('ip', '').split()[0]})"
            private = ""
            if _is_private(i.get("ip", "")):
                private = (" Its address is private, so it is reachable from the internet only if an "
                           "upstream device forwards to it.")
            if _has_admin_deny(local_in or [], i["name"]):
                add("info", "wan_admin_access", i["name"],
                    f"WAN interface {where} allows {', '.join(exposed)}, limited by a local-in allowlist.{private}",
                    "Keep the local-in allowlist current; removing admin access from the WAN is stricter still")
            else:
                add("critical" if open_admins else "warn", "wan_admin_access", i["name"],
                    f"WAN interface {where} allows {', '.join(exposed)}.{private}",
                    "Remove admin access from WAN interfaces, or restrict it with a local-in policy")
        cleartext = [s for s in (i.get("allowaccess") or "").split() if s in ("http", "telnet")]
        if cleartext:
            add("warn", "cleartext_admin", i["name"], f"Allows cleartext {', '.join(cleartext)}",
                "Remove http/telnet from allowaccess")

    if version and not _supports_pbkdf2(version):
        add("critical", "password_hashing", firmware,
            "This firmware stores admin passwords as SHA-256, which can be cracked offline",
            "Upgrade to 7.2.11, 7.4.8, 7.6.1 or later, then have every admin log in once")
    # 7.2 and 7.4 call the setting login-lockout-upon-downgrade.
    lockout_key = (
        "login-lockout-upon-weaker-encryption" if version[:2] >= (7, 6) else "login-lockout-upon-downgrade"
    )
    if check_hashes:
        try:
            hashes = _admin_hashes(await _backup_text(client, v))
        except (FortiGateAPIError, RuntimeError) as e:
            hashes = {}
            add("info", "not_checked", "password hashes", f"Could not read a config backup: {e}",
                "Run with a token that can back up the configuration")
        for name, h in hashes.items():
            if h.get("password") == "SH2":
                add("warn", "legacy_hash", name,
                    "Password is still stored as SHA-256 (the admin hasn't logged in since the upgrade)",
                    "Have this admin log in once, or reset the password")
            lockout_off = isinstance(pw_policy, dict) and pw_policy.get(lockout_key) == "disable"
            if h.get("old-password") == "SH2" and lockout_off:
                add("warn", "legacy_hash", name,
                    f"An old SHA-256 copy of the password is kept ({lockout_key} is disabled)",
                    f"set {lockout_key} enable under config system password-policy; downgrading "
                    "below the PBKDF2 releases then locks every admin out")

    findings.sort(key=lambda f: SEVERITY[f["severity"]])
    counts = {s: sum(f["severity"] == s for f in findings) for s in SEVERITY}

    def refs(value: Any) -> Any:
        return [r.get("name") for r in value] if isinstance(value, list) else value

    keys = ("policyid", "status", "action", "intf", "srcaddr", "service", "internet-service-src-name")
    policies = [{k: refs(p.get(k)) for k in keys} for p in local_in or []]
    return {"firmware": firmware, "summary": counts, "findings": findings, "local_in_policies": policies}


async def _extra_findings(client: FortiGateClient, v: dict[str, Any], is_eval: bool) -> list[dict[str, Any]]:
    """Findings from the FortiGuard, policy protection, log target and HA checks, in the audit's shape."""
    from . import _logtargets, fortiguard, profiles

    fgd, prot, logs_, ha = await asyncio.gather(
        fortiguard.fortiguard_status(client, v), profiles.audit_protection(client, v),
        _logtargets.log_targets(client, v), access.ha_status(client, v))
    out: list[dict[str, Any]] = []
    for f in fgd.get("findings", []):
        out.append({**f, "object": "FortiGuard"})
    for f in prot.get("findings", []):
        if is_eval and f["check"] == "unlicensed_profile":
            continue  # covered by not_applicable_on_evaluation_license
        sev = "info" if is_eval and f["check"] == "no_ips" else f["severity"]
        out.append({"severity": sev, "check": f["check"], "object": f"policy {f['policy']}",
                    "detail": f["detail"], "fix": f["fix"]})
    for f in logs_.get("findings", []):
        if f["check"] != "no_remote_logging":  # hardening_checks reports this as remote_logging
            out.append(f)
    for f in ha.get("findings", []):
        out.append({**f, "object": "HA"})
    return out


async def audit_hardening(
    client: FortiGateClient, v: dict[str, Any], check_hashes: bool = True
) -> dict[str, Any]:
    admin = await audit_admin_access(client, v, check_hashes)
    info = await license_info(client, v)
    is_eval = info.is_eval
    admins_open = any(f["check"] == "admin_trusthosts" for f in admin["findings"])

    findings = (admin["findings"] + await hardening_checks(client, v, is_eval, admins_open)
                + await _extra_findings(client, v, is_eval))
    findings = annotate(findings, is_eval)
    out: dict[str, Any] = {
        "firmware": admin["firmware"],
        "license": info.vm_status,
        "summary": {s: sum(f["severity"] == s for f in findings) for s in SEVERITY},
        "findings": findings,
        "fix_plan": fix_plan(findings),
        "local_in_policies": admin["local_in_policies"],
    }
    if is_eval:
        out["not_applicable_on_evaluation_license"] = EVAL_NOT_APPLICABLE
    return out


async def handle(name: str, args: dict[str, Any], client: FortiGateClient) -> Any:
    if name in {t["name"] for t in access.TOOLS}:
        return await access.handle(name, args, client)
    v = vdom_param(args)

    if name == "get_system_status":
        resp = await client.get("/api/v2/monitor/system/status", v)
        # Serial, version and build sit beside "results", not inside it.
        out: dict[str, Any] = {}
        if isinstance(resp, dict):
            out = {k: resp[k] for k in ("serial", "version", "build") if k in resp}
        res = results(resp)
        out.update(res if isinstance(res, dict) else {"results": res})
        # system/status has no uptime; the GUI computes it from web-ui/state's reboot time.
        try:
            ui = results(await client.get("/api/v2/monitor/web-ui/state", v))
        except FortiGateAPIError:
            ui = None
        if isinstance(ui, dict) and ui.get("utc_last_reboot") and ui.get("snapshot_utc_time"):
            seconds = max(0, (ui["snapshot_utc_time"] - ui["utc_last_reboot"]) // 1000)
            days, rest = divmod(seconds, 86400)
            out["last_reboot"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ui["utc_last_reboot"] / 1000))
            out["uptime_seconds"] = seconds
            out["uptime"] = f"{days}d {rest // 3600}h {rest % 3600 // 60}m"
        return out

    elif name == "get_license_status":
        lic = results(await client.get("/api/v2/monitor/license/status", v))
        if args.get("all") or not isinstance(lic, dict):
            return lic
        return {k: lic.get(k) for k in ("vm", "forticare", "fortiguard", "forticloud")}

    elif name == "get_license_limits":
        return await capacity(client, v)

    elif name == "get_license_features":
        return features_report(await license_info(client, v, refresh=True))

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

    elif name == "audit_admin_access":
        return await audit_admin_access(client, v, args.get("check_hashes", True))

    elif name == "audit_hardening":
        return await audit_hardening(client, v, args.get("check_hashes", True))

    elif name == "backup_config":
        text = await _backup_text(client, v)
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

    elif name == "activate_vm_eval_license":
        if args.get("confirm") is not True:
            raise ValueError("Set confirm=true: activating the license reboots the FortiGate")
        lic = results(await client.get("/api/v2/monitor/license/status", v))
        vm = lic.get("vm", {}) if isinstance(lic, dict) else {}
        if vm.get("valid"):
            return {"status": "already_licensed", "vm": vm}
        account = os.environ.get("FORTICLOUD_ACCOUNT", "")
        password = os.environ.get("FORTICLOUD_PASSWORD", "")
        if not account or not password:
            raise ValueError("Set FORTICLOUD_ACCOUNT and FORTICLOUD_PASSWORD in the server's environment")
        await client.post(
            "/api/v2/monitor/system/vmlicense/download-eval",
            {"account_id": account, "account_password": password,
             "is_government": bool(args.get("is_government", False))},
            v,
        )
        return {
            "status": "success",
            "note": "License downloaded; the FortiGate now reboots (about a minute). Check get_license_status afterwards.",
        }

    raise ValueError(f"Unknown tool: {name}")
