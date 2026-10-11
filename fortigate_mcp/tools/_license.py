"""What the FortiGate is licensed for, read once from monitor/license/status and shared by tools.

The same FortiOS runs on the free FortiGate-VM evaluation license and on paid units; what differs
is which FortiGuard services are entitled. Tools use this to apply evaluation limits only where
they exist, and to explain an unlicensed feature instead of failing with a bare 401 or returning
stale data.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from ..client import FortiGateAPIError, FortiGateClient
from ._common import results

LICENSE_PATH = "/api/v2/monitor/license/status"
CACHE_SECONDS = 60

# Statuses FortiOS reports per service. Only these two mean the service is usable now.
ACTIVE = {"licensed", "expires_soon"}

# Friendly feature names -> key in license/status. Values not seen on a paid unit yet are
# documented as unverified in ADR-0002.
FEATURES = {
    "fortiguard": "fortiguard",
    "forticare": "forticare",
    "antivirus": "antivirus",
    "ips": "ips",
    "app_control": "appctrl",
    "web_filter": "web_filtering",
    "internet_service_db": "internet_service_db",
    "botnet_domains": "botnet_domain",
    "malicious_urls": "malicious_urls",
    "dlp": "data_leak_prevention",
    "antispam": "antispam",
    "outbreak_prevention": "outbreak_prevention",
    "iot_detection": "iot_detection",
    "device_os_id": "device_os_id",
    "geoip_db": "geoip_db",
    "firmware_updates": "firmware_updates",
    "security_rating": "security_rating",
    "forticloud_logging": "forticloud_logging",
    "fortianalyzer_cloud": "fortianalyzer_cloud",
    "forticloud_sandbox": "forticloud_sandbox",
}


@dataclass
class License:
    vm_status: str | None
    is_eval: bool
    is_vm: bool
    fortiguard_connected: bool | None
    services: dict[str, dict[str, Any]] = field(default_factory=dict)
    vdoms: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    def status(self, feature: str) -> str | None:
        return (self.services.get(feature) or {}).get("status")

    def has(self, feature: str) -> bool:
        return self.status(feature) in ACTIVE

    def require(self, feature: str, what: str) -> None:
        """Raise a clear error when a tool needs a FortiGuard service the unit isn't licensed for."""
        if self.has(feature):
            return
        status = self.status(feature) or "unknown"
        where = "the free evaluation license" if self.is_eval else "this FortiGate's contract"
        raise FortiGateLicenseError(
            f"{what} needs the FortiGuard {feature.replace('_', ' ')} service, which {where} doesn't "
            f"include (license status: {status}). Check get_license_features for what is licensed."
        )


class FortiGateLicenseError(RuntimeError):
    pass


def _service(entry: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"status": entry.get("status")}
    for key in ("expires", "version", "last_update", "last_update_result_status"):
        if entry.get(key) not in (None, ""):
            out[key] = entry[key]
    return out


def parse(lic: Any) -> License:
    lic = lic if isinstance(lic, dict) else {}
    vm = lic.get("vm") if isinstance(lic.get("vm"), dict) else {}
    fgd = lic.get("fortiguard") if isinstance(lic.get("fortiguard"), dict) else {}
    services = {
        name: _service(lic[key]) for name, key in FEATURES.items() if isinstance(lic.get(key), dict)
    }
    # fortiguard and forticare are connection/contract entries rather than services.
    if fgd:
        services["fortiguard"] = {"status": "licensed" if fgd.get("supported") else "no_support",
                                  "connected": fgd.get("connected")}
    return License(
        vm_status=vm.get("status"),
        is_eval=vm.get("status") == "vm_eval",
        is_vm=bool(vm),
        fortiguard_connected=fgd.get("connected") if fgd else None,
        services=services,
        vdoms={k: lic["vdom"][k] for k in ("used", "max") if k in (lic.get("vdom") or {})},
        raw=lic,
    )


async def license_info(client: FortiGateClient, v: dict[str, Any], refresh: bool = False) -> License:
    """The parsed license, cached on the client for CACHE_SECONDS."""
    cached = getattr(client, "_license_cache", None)
    if cached and not refresh and time.monotonic() - cached[0] < CACHE_SECONDS:
        return cached[1]
    try:
        info = parse(results(await client.get(LICENSE_PATH, v)))
    except FortiGateAPIError:
        info = parse({})
    client._license_cache = (time.monotonic(), info)  # type: ignore[attr-defined]
    return info


def _age_days(epoch: Any, now: float) -> int | None:
    return int((now - epoch) // 86400) if isinstance(epoch, (int, float)) and epoch > 978400000 else None


def features_report(info: License, now: float | None = None) -> dict[str, Any]:
    """What is licensed, what isn't, and how old the signature databases are."""
    now = now or time.time()
    licensed, not_licensed, expiring = [], [], []
    signatures = {}
    for name, svc in info.services.items():
        status = svc.get("status")
        (licensed if status in ACTIVE else not_licensed).append(name)
        expires = svc.get("expires")
        if status == "expires_soon" or (isinstance(expires, (int, float)) and 0 < expires - now < 30 * 86400):
            expiring.append({"feature": name, "expires": time.strftime("%Y-%m-%d", time.gmtime(expires))
                             if isinstance(expires, (int, float)) else None})
        if "version" in svc:
            signatures[name] = {"version": svc["version"], "age_days": _age_days(svc.get("last_update"), now),
                                "last_update_result": svc.get("last_update_result_status")}
    edition = ("FortiGate-VM evaluation (free)" if info.is_eval
               else "FortiGate-VM (licensed)" if info.is_vm and info.vm_status == "vm_valid"
               else f"FortiGate-VM ({info.vm_status})" if info.is_vm
               else "Hardware FortiGate")
    out: dict[str, Any] = {
        "edition": edition,
        "vm_license": info.vm_status,
        "fortiguard_connected": info.fortiguard_connected,
        "licensed": sorted(licensed),
        "not_licensed": sorted(not_licensed),
        "expiring_within_30_days": expiring,
        "signature_databases": signatures,
        "vdoms": info.vdoms,
    }
    if info.is_eval:
        out["note"] = ("The free evaluation license includes no FortiGuard services: signature databases "
                       "stay at their factory versions and rating lookups don't run. It also caps the unit "
                       "at 1 vCPU, 2 GB RAM, 3 interfaces, 3 firewall policies and 3 static routes "
                       "(get_license_limits).")
    elif info.fortiguard_connected is False:
        out["note"] = "Licensed, but not connected to FortiGuard, so updates and lookups are failing."
    return out
