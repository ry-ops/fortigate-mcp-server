"""Security profiles (IPS, antivirus, web/DNS filter, application control...) and whether policies use them.

A profile only protects traffic when an accept policy references it, the policy has security
profiles enabled, the inspection mode can see the content, and, for FortiGuard-backed features,
the unit is licensed for the service. These tools check all four. Licensed-unit behaviour is
modelled on FortiOS 7.6's schema and not yet verified on a licensed device.
"""

from __future__ import annotations

import asyncio
from typing import Any

from ..client import FortiGateAPIError, FortiGateClient
from ._common import STR, results, schema, vdom_param
from ._license import License, license_info

# kind -> (cmdb endpoint, firewall policy field, FortiGuard service, what happens without it)
KINDS: dict[str, tuple[str, str, str | None, str]] = {
    "ips": ("ips/sensor", "ips-sensor", "ips",
            "runs on the signatures bundled with the firmware, which never update"),
    "antivirus": ("antivirus/profile", "av-profile", "antivirus",
                  "has no usable virus signatures, so it detects almost nothing"),
    "webfilter": ("webfilter/profile", "webfilter-profile", "web_filter",
                  "can't rate URLs, so category rules never match; static URL filters still work"),
    "dnsfilter": ("dnsfilter/profile", "dnsfilter-profile", "web_filter",
                  "can't rate domains, so category and botnet blocking don't work; static domain filters still do"),
    "application": ("application/list", "application-list", "app_control",
                    "identifies applications from the bundled signatures, which never update"),
    "emailfilter": ("emailfilter/profile", "emailfilter-profile", "antispam",
                    "can't query FortiGuard spam ratings; local block/allow lists still work"),
    "dlp": ("dlp/profile", "dlp-profile", "dlp", "has no FortiGuard DLP patterns; custom patterns still work"),
    "file-filter": ("file-filter/profile", "file-filter-profile", None, ""),
    "waf": ("waf/profile", "waf-profile", None, ""),
    "videofilter": ("videofilter/profile", "videofilter-profile", None, ""),
    "ssh-filter": ("ssh-filter/profile", "ssh-filter-profile", None, ""),
    "virtual-patch": ("virtual-patch/profile", "virtual-patch-profile", None, ""),
}
# Content scanners that need deep inspection to see inside HTTPS.
NEEDS_DEEP = ("antivirus", "dlp", "file-filter")
SHALLOW = {"no-inspection", "certificate-inspection"}

TOOLS = [
    {
        "name": "list_security_profiles",
        "description": (
            "Security profiles by kind (ips, antivirus, webfilter, dnsfilter, application, "
            "emailfilter, dlp, file-filter, waf, videofilter, ssh-filter, virtual-patch), each with "
            "the firewall policies that use it, and whether the FortiGuard service behind the kind is "
            "licensed (and what the profile can still do if not). Read or change a profile's settings "
            "with get_config / set_config on the endpoint shown."
        ),
        "inputSchema": schema({"kind": STR("One kind only (optional), e.g. ips")}),
    },
    {
        "name": "audit_policy_protection",
        "description": (
            "Check that accept policies are actually protected: traffic from or to a WAN interface "
            "with no IPS sensor, profiles attached while security profiles are disabled on the policy, "
            "antivirus/DLP/file filter with an inspection profile that can't see inside HTTPS, "
            "profiles whose FortiGuard service isn't licensed, and policies that don't log. Read-only."
        ),
        "inputSchema": schema({}),
    },
]


def _license_note(info: License, kind: str) -> dict[str, Any]:
    _, _, service, effect = KINDS[kind]
    if service is None:
        return {"license": "not needed"}
    if info.has(service):
        return {"license": "licensed"}
    status = info.status(service) or "unknown"
    return {"license": f"not licensed ({status})", "without_license": f"This profile {effect}."}


async def _read(client: FortiGateClient, path: str, v: dict[str, Any], params: dict[str, Any] | None = None) -> Any:
    try:
        return results(await client.get(path, {**v, **(params or {})}))
    except FortiGateAPIError:
        return None


async def _policies(client: FortiGateClient, v: dict[str, Any]) -> list[dict[str, Any]]:
    fields = ["policyid", "name", "status", "action", "srcintf", "dstintf", "utm-status", "ssl-ssh-profile",
              "logtraffic", "inspection-mode"] + [k[1] for k in KINDS.values()]
    pols = await _read(client, "/api/v2/cmdb/firewall/policy", v, {"format": "|".join(fields)})
    return pols if isinstance(pols, list) else []


def _label(p: dict[str, Any]) -> str:
    return f"{p.get('policyid')}:{p.get('name') or '(unnamed)'}"


async def list_profiles(client: FortiGateClient, v: dict[str, Any], kind: str | None) -> dict[str, Any]:
    kinds = [kind] if kind else list(KINDS)
    unknown = [k for k in kinds if k not in KINDS]
    if unknown:
        raise ValueError(f"Unknown kind {unknown[0]}; one of {', '.join(KINDS)}")
    info, policies = await asyncio.gather(license_info(client, v), _policies(client, v))
    lists = await asyncio.gather(*(_read(client, f"/api/v2/cmdb/{KINDS[k][0]}", v, {"format": "name|comment"})
                                   for k in kinds))
    out: dict[str, Any] = {}
    for k, profs in zip(kinds, lists, strict=True):
        if not isinstance(profs, list):
            continue
        field = KINDS[k][1]
        out[k] = {
            "endpoint": KINDS[k][0],
            **_license_note(info, k),
            "profiles": [{
                "name": p.get("name"),
                "comment": p.get("comment", ""),
                "used_by": [_label(pol) for pol in policies if pol.get(field) == p.get("name")],
            } for p in profs],
        }
    return out


async def audit_protection(client: FortiGateClient, v: dict[str, Any]) -> dict[str, Any]:
    info, policies, ifaces = await asyncio.gather(
        license_info(client, v), _policies(client, v),
        _read(client, "/api/v2/cmdb/system/interface", v, {"format": "name|role"}))
    wan = {i["name"] for i in ifaces or [] if isinstance(i, dict) and i.get("role") == "wan"}
    findings: list[dict[str, Any]] = []

    def add(severity: str, check: str, pol: dict[str, Any], detail: str, fix: str) -> None:
        findings.append({"severity": severity, "check": check, "policy": _label(pol), "detail": detail, "fix": fix})

    def names(value: Any) -> set[str]:
        return {r.get("name") for r in value} if isinstance(value, list) else set()

    summary = []
    for pol in policies:
        if pol.get("action") != "accept" or pol.get("status") == "disable":
            continue
        attached = {k: pol.get(KINDS[k][1]) for k in KINDS if pol.get(KINDS[k][1])}
        utm_on = pol.get("utm-status") == "enable"
        ssl = pol.get("ssl-ssh-profile") or "no-inspection"
        from_wan, to_wan = bool(names(pol.get("srcintf")) & wan), bool(names(pol.get("dstintf")) & wan)
        summary.append({"policy": _label(pol), "direction": "inbound" if from_wan else "outbound" if to_wan else "internal",
                        "security_profiles": utm_on, "profiles": attached, "ssl_ssh_profile": ssl})

        if attached and not utm_on:
            add("warn", "profiles_ignored", pol, f"Profiles attached ({', '.join(attached)}) but security profiles are "
                "disabled on the policy, so none of them run", "set utm-status enable on the policy")
        if (from_wan or to_wan) and not (utm_on and attached.get("ips")):
            direction = "from" if from_wan else "to"
            add("warn" if from_wan else "info", "no_ips", pol,
                f"Traffic {direction} a WAN interface without an IPS sensor",
                "Attach an IPS sensor (e.g. ips-sensor default, or protect_http_server for published servers) "
                "with update_firewall_policy")
        if utm_on:
            blind = [k for k in NEEDS_DEEP if attached.get(k)]
            if blind and ssl in SHALLOW:
                add("info", "https_not_inspected", pol,
                    f"{', '.join(blind)} can't see inside HTTPS with ssl-ssh-profile {ssl}",
                    "Use a deep-inspection profile (clients must trust its CA), or accept that only HTTP is scanned")
            for k in attached:
                service = KINDS[k][2]
                if service and not info.has(service):
                    status = info.status(service) or "unknown"
                    add("info" if info.is_eval else "warn", "unlicensed_profile", pol,
                        f"{k} profile '{attached[k]}' {KINDS[k][3]} (FortiGuard {service.replace('_', ' ')}: {status})",
                        "Renew or add the FortiGuard service" if not info.is_eval else
                        "Expected on the evaluation license; rely on narrow service allowlists")
        if pol.get("logtraffic") == "disable":
            add("info", "no_logging", pol, "Traffic on this policy isn't logged",
                "set logtraffic all (or utm) on the policy")

    severity = {"critical": 0, "warn": 1, "info": 2}
    findings.sort(key=lambda f: severity[f["severity"]])
    out: dict[str, Any] = {
        "summary": {s: sum(f["severity"] == s for f in findings) for s in severity},
        "policies": summary,
        "findings": findings,
    }
    if info.is_eval:
        out["note"] = ("On the evaluation license IPS and application control run on old bundled signatures and the "
                       "rating-based features don't work, so attaching profiles adds little; service allowlists "
                       "on each policy are the effective control.")
    return out


async def handle(name: str, args: dict[str, Any], client: FortiGateClient) -> Any:
    v = vdom_param(args)
    if name == "list_security_profiles":
        return await list_profiles(client, v, args.get("kind"))
    elif name == "audit_policy_protection":
        return await audit_protection(client, v)
    raise ValueError(f"Unknown tool: {name}")
