"""Hardening checks beyond admin access: management plane, crypto, VPN, logging, accounts, services.

audit_hardening runs audit_admin_access and these checks together, tags every finding with the
order to fix it in and whether the fix can cut off admin access, and accounts for the FortiGate-VM
evaluation license, where FortiGuard services are unavailable.
"""

from __future__ import annotations

import asyncio
from typing import Any

from ..client import FortiGateAPIError, FortiGateClient
from ._common import results

ADMIN_SERVICES = ("https", "ssh", "http", "telnet")
WEAK_TLS = ("sslv3", "tlsv1-0", "tlsv1-1", "tls1-0", "tls1-1")
SEVERITY = {"critical": 0, "warn": 1, "info": 2}

# check -> (section, fix order, lockout risk). Fix in ascending order: changes that cannot
# affect access first, then the ones that narrow who can log in, then account changes that
# depend on a working replacement login.
CHECKS: dict[str, tuple[str, int, bool]] = {
    "implicit_deny_log": ("logging", 1, False),
    "local_in_deny_log": ("logging", 1, False),
    "remote_logging": ("logging", 1, False),
    "admin_telnet": ("management", 1, False),
    "cleartext_admin": ("management", 1, False),
    "ssl_vpn": ("vpn", 1, False),
    "forticloud_sso": ("management", 1, False),
    "password_policy": ("accounts", 1, False),
    "admin_session": ("management", 1, False),
    "ntp_server": ("services", 1, False),
    "strong_crypto": ("crypto", 2, False),
    "admin_tls": ("crypto", 2, False),
    "lan_admin_access": ("management", 3, True),
    "wan_admin_access": ("management", 4, True),
    "admin_trusthosts": ("management", 4, True),
    "local_in_admin": ("management", 4, True),
    "api_user_trusthosts": ("accounts", 4, True),
    "api_user_profile": ("accounts", 5, True),
    "admin_mfa": ("accounts", 6, True),
    "default_admin": ("accounts", 6, True),
    "legacy_hash": ("accounts", 7, True),
    "password_hashing": ("firmware", 0, False),
    "fortiguard_servers": ("fortiguard", 1, False),
    "fortiguard_connection": ("fortiguard", 1, False),
    "stale_signatures": ("fortiguard", 1, False),
    "update_schedule": ("fortiguard", 1, False),
    "unlicensed_profile": ("protection", 1, False),
    "no_logging": ("logging", 1, False),
    "syslog_cleartext": ("logging", 1, False),
    "faz_cert_verification": ("logging", 1, False),
    "cloud_unlicensed": ("logging", 1, False),
    "profiles_ignored": ("protection", 2, False),
    "no_ips": ("protection", 2, False),
    "https_not_inspected": ("protection", 2, False),
    "out_of_sync": ("ha", 2, False),
    "hb_encryption": ("ha", 2, False),
    "hb_authentication": ("ha", 2, False),
    "single_heartbeat": ("ha", 2, False),
    "session_pickup": ("ha", 2, False),
    "not_checked": ("audit", 9, False),
}

# What stops working, or never starts, on the evaluation license, and what to rely on instead.
EVAL_NOT_APPLICABLE = [
    {"item": "FortiToken MFA", "reason": "Tokens are activated through FortiGuard, which the evaluation license can't reach",
     "instead": "Trusted hosts on every admin plus a local-in policy limiting who reaches HTTPS/SSH"},
    {"item": "IPS, antivirus, web filter and DNS filter", "reason": "No FortiGuard signature or rating updates",
     "instead": "Narrow service allowlists on policies; IPS still runs on the built-in signatures"},
    {"item": "Internet Service Database sources in policies", "reason": "The database isn't updated without FortiGuard",
     "instead": "Address objects you maintain"},
    {"item": "Firmware updates from FortiGuard", "reason": "Images can't be downloaded on the evaluation license",
     "instead": "Upload images by hand and check https://www.fortiguard.com/psirt for the running release"},
    {"item": "FortiGuard and FortiAnalyzer Cloud logging", "reason": "Not included with the evaluation license",
     "instead": "Syslog to a collector you run"},
]


def _names(value: Any) -> list[str]:
    return [r.get("name", "") for r in value] if isinstance(value, list) else []


def _admin_services(iface: dict[str, Any]) -> list[str]:
    return [s for s in (iface.get("allowaccess") or "").split() if s in ADMIN_SERVICES]


def _has_admin_deny(local_in: list[dict[str, Any]], iface: str) -> bool:
    """A local-in deny from 'all' covering HTTPS/SSH on this interface (what follows an admin allowlist)."""
    for p in local_in:
        if p.get("status") == "disable" or p.get("action") != "deny":
            continue
        if not {"any", iface} & set(_names(p.get("intf"))):
            continue
        if "all" not in _names(p.get("srcaddr")):
            continue
        if {"ALL", "HTTPS", "SSH"} & set(_names(p.get("service"))):
            return True
    return False


async def hardening_checks(
    client: FortiGateClient, v: dict[str, Any], is_eval: bool, admins_open: bool
) -> list[dict[str, Any]]:
    """Findings for the checks audit_admin_access doesn't cover."""
    findings: list[dict[str, Any]] = []

    def add(severity: str, check: str, obj: str, detail: str, fix: str) -> None:
        findings.append({"severity": severity, "check": check, "object": obj, "detail": detail, "fix": fix})

    async def read(path: str, params: dict[str, Any] | None = None) -> Any:
        try:
            return results(await client.get(path, {**v, **(params or {})}))
        except FortiGateAPIError as e:
            add("info", "not_checked", path, f"Could not read: {e}", "Use a token with read access to this path")
            return None

    (glob, interfaces, local_in, log_setting, syslog, faz, fgd_log,
     ssl_vpn, pw_policy, ntp, dhcp, status) = await asyncio.gather(
        read("/api/v2/cmdb/system/global"),
        read("/api/v2/cmdb/system/interface"),
        read("/api/v2/cmdb/firewall/local-in-policy"),
        read("/api/v2/cmdb/log/setting"),
        read("/api/v2/cmdb/log.syslogd/setting"),
        read("/api/v2/cmdb/log.fortianalyzer/setting"),
        read("/api/v2/cmdb/log.fortiguard/setting"),
        read("/api/v2/cmdb/vpn.ssl/settings"),
        read("/api/v2/cmdb/system/password-policy"),
        read("/api/v2/cmdb/system/ntp"),
        read("/api/v2/cmdb/system.dhcp/server"),
        read("/api/v2/monitor/system/status"),
    )
    glob = glob if isinstance(glob, dict) else {}
    interfaces = interfaces if isinstance(interfaces, list) else []
    local_in = local_in if isinstance(local_in, list) else []

    # Management plane. WAN exposure and cleartext protocols are audit_admin_access's checks.
    for i in interfaces:
        exposed = _admin_services(i)
        if not exposed:
            continue
        if i.get("role") != "wan":
            add("warn" if admins_open else "info", "lan_admin_access", i["name"],
                f"{i['name']} ({(i.get('ip') or '').split()[0]}) allows {', '.join(exposed)}, so every host "
                "on that network can reach the login page",
                "Remove admin access from interfaces you don't manage the FortiGate through; keep ping if needed")
        if not _has_admin_deny(local_in, i["name"]):
            add("info", "local_in_admin", i["name"],
                f"No local-in policy limits which sources reach {', '.join(exposed)} on {i['name']}",
                "Add a local-in accept for your admin addresses on HTTPS/SSH, then a deny from all. "
                "Local-in policies don't count against the evaluation license's 3 firewall policies")
    if glob.get("admin-telnet") == "enable":
        add("info", "admin_telnet", "system global", "Telnet administration is enabled globally",
            "set admin-telnet disable under config system global")
    if glob.get("admin-forticloud-sso-login") == "enable":
        add("warn", "forticloud_sso", "system global",
            "FortiCloud SSO admin login is enabled (abused through CVE-2026-24858 in January 2026)",
            "set admin-forticloud-sso-login disable unless you rely on it, and keep firmware current")
    timeout = glob.get("admintimeout")
    if isinstance(timeout, int) and timeout > 15:
        add("info", "admin_session", "system global", f"Idle admin sessions last {timeout} minutes",
            "Lower admintimeout to 15 minutes or less")
    threshold = glob.get("admin-lockout-threshold")
    if isinstance(threshold, int) and threshold > 5:
        add("info", "admin_session", "system global", f"Admin lockout only after {threshold} failed logins",
            "Lower admin-lockout-threshold to 5 or less")

    # Crypto. The evaluation license is a low-encryption build, so these may be refused there.
    eval_note = " The evaluation license may refuse this." if is_eval else ""
    if glob.get("strong-crypto") == "disable":
        add("info" if is_eval else "warn", "strong_crypto", "system global",
            "Weak ciphers are allowed for HTTPS and SSH administration." + eval_note,
            "set strong-crypto enable under config system global, then check that you can still log in")
    weak_admin = [t for t in (glob.get("admin-https-ssl-versions") or "").split() if t in WEAK_TLS]
    if weak_admin:
        add("warn", "admin_tls", "system global", f"Admin HTTPS accepts {', '.join(weak_admin)}",
            "set admin-https-ssl-versions tlsv1-2 tlsv1-3")
    if (glob.get("ssl-min-proto-version") or "").lower() in WEAK_TLS:
        add("info", "admin_tls", "system global",
            f"Connections the FortiGate makes itself allow {glob['ssl-min-proto-version']}." + eval_note,
            "set ssl-min-proto-version TLSv1-2 under config system global")

    # SSL VPN (Agentless VPN on 7.6). It listens only on its source interfaces.
    if isinstance(ssl_vpn, dict) and ssl_vpn.get("status") == "enable":
        listening = _names(ssl_vpn.get("source-interface"))
        weak = (ssl_vpn.get("ssl-min-proto-ver") or "").lower() in WEAK_TLS
        tls = f", and accepts {ssl_vpn['ssl-min-proto-ver']}" if weak else ""
        if listening:
            wan = {i["name"] for i in interfaces if i.get("role") == "wan"}
            add("critical" if wan & set(listening) else "warn", "ssl_vpn", "vpn ssl settings",
                f"SSL VPN listens on {', '.join(listening)} port {ssl_vpn.get('port')}{tls}",
                "Disable it if unused; otherwise require TLS 1.2+, MFA and a source allowlist")
        else:
            add("info", "ssl_vpn", "vpn ssl settings",
                f"SSL VPN is enabled but listens on no interface{tls}; one setting away from exposure",
                "set status disable under config vpn ssl settings")

    # Logging.
    if isinstance(log_setting, dict):
        if log_setting.get("fwpolicy-implicit-log") == "disable":
            add("warn", "implicit_deny_log", "log setting",
                "Traffic dropped by the implicit deny isn't logged, so blocked connections are invisible",
                "set fwpolicy-implicit-log enable under config log setting")
        if log_setting.get("local-in-deny-unicast") == "disable":
            add("warn", "local_in_deny_log", "log setting",
                "Denied connections to the FortiGate itself (login probes, scans) aren't logged",
                "set local-in-deny-unicast enable under config log setting")
    remote = [name for name, s in (("syslog", syslog), ("FortiAnalyzer", faz), ("FortiGuard cloud", fgd_log))
              if isinstance(s, dict) and s.get("status") == "enable"]
    has_disk = isinstance(status, dict) and status.get("log_disk_status") not in (None, "not_available")
    if not remote:
        where = "disk only" if has_disk else "memory only, and lost on reboot"
        add("warn", "remote_logging", "log targets", f"No remote log target; logs are kept in {where}",
            "Send logs to a syslog collector (config log syslogd setting)")

    # Accounts.
    if isinstance(pw_policy, dict):
        if pw_policy.get("status") == "disable":
            add("warn", "password_policy", "password policy", "No admin password policy is enforced",
                "Enable it with a minimum length of 12 or more")
        else:
            if (pw_policy.get("minimum-length") or 0) < 12:
                add("info", "password_policy", "password policy",
                    f"Minimum admin password length is {pw_policy.get('minimum-length')}",
                    "Set minimum-length to 12 or more")
            if pw_policy.get("reuse-password") == "enable":
                add("info", "password_policy", "password policy", "Admins can reuse old passwords",
                    "set reuse-password disable")

    # Services the FortiGate offers its networks.
    if isinstance(ntp, dict):
        ntp_ifaces = set(_names_any(ntp.get("interface"), "interface-name"))
        if ntp.get("server-mode") == "enable" and ntp_ifaces:
            add("info", "ntp_server", ", ".join(sorted(ntp_ifaces)),
                f"The FortiGate answers NTP on {', '.join(sorted(ntp_ifaces))}",
                "Limit server mode to interfaces whose hosts use the FortiGate for time")
        for d in dhcp if isinstance(dhcp, list) else []:
            if d.get("status") != "disable" and d.get("ntp-service") == "local" and (
                ntp.get("server-mode") != "enable" or d.get("interface") not in ntp_ifaces
            ):
                add("info", "ntp_server", d.get("interface", ""),
                    f"DHCP on {d.get('interface')} gives clients the FortiGate as their NTP server, "
                    "but NTP server mode isn't enabled there, so their time queries go unanswered",
                    f"Add {d.get('interface')} to config system ntp interface, or hand out another NTP server")

    return findings


def _names_any(value: Any, key: str) -> list[str]:
    return [r.get(key) or r.get("name", "") for r in value] if isinstance(value, list) else []


def annotate(findings: list[dict[str, Any]], is_eval: bool) -> list[dict[str, Any]]:
    """Add section, fix order and lockout risk; add evaluation-license context where it changes the fix."""
    for f in findings:
        section, order, lockout = CHECKS.get(f["check"], ("other", 8, False))
        f.update(section=section, order=order, lockout_risk=lockout)
        if is_eval and f["check"] == "admin_mfa":
            f["fix"] = ("FortiToken can't be activated on the evaluation license. Rely on trusted hosts and a "
                        "local-in policy instead, or configure email two-factor if the FortiGate can send mail")
    findings.sort(key=lambda f: (SEVERITY[f["severity"]], f["order"]))
    return findings


def fix_plan(findings: list[dict[str, Any]]) -> list[str]:
    """One line per finding in the order to fix them, marking the ones that can cut off access."""
    plan = sorted((f for f in findings if f["check"] != "not_checked"), key=lambda f: (f["order"], f["check"]))
    return [
        f"{f['order']}. {f['check']} ({f['object']}): {f['fix']}" + (" [LOCKOUT RISK]" if f["lockout_risk"] else "")
        for f in plan
    ]
