"""How much of the FortiGate-VM evaluation license's object limits is in use.

The permanent evaluation license (status vm_eval) allows at most 3 interfaces, 3 firewall
policies and 3 static routes. FortiOS does not report these limits through the API, so they are
applied here whenever the VM license is the evaluation one.
"""

from __future__ import annotations

from typing import Any

from ..client import FortiGateClient
from ._common import results

EVAL_LIMITS = {"policies": 3, "static_routes": 3, "interfaces": 3}
# Built-in or virtual interfaces that exist on every FortiGate-VM and are not user ports.
_BUILTIN_TYPES = {"tunnel", "vap-switch", "loopback", "ssl"}
_BUILTIN_NAMES = {"fortilink", "default-mesh"}


def _in_use(iface: dict[str, Any]) -> bool:
    if iface.get("name") in _BUILTIN_NAMES or iface.get("type") in _BUILTIN_TYPES:
        return False
    if iface.get("type") == "vlan":
        return True
    has_ip = (iface.get("ip") or "0.0.0.0 0.0.0.0").split()[0] != "0.0.0.0"
    return has_ip or iface.get("mode") in ("dhcp", "pppoe")


async def capacity(client: FortiGateClient, v: dict[str, Any]) -> dict[str, Any]:
    lic = results(await client.get("/api/v2/monitor/license/status", v))
    vm = lic.get("vm", {}) if isinstance(lic, dict) else {}
    is_eval = vm.get("status") == "vm_eval"

    policies = results(await client.get("/api/v2/cmdb/firewall/policy", {**v, "format": "policyid|name"}))
    routes = results(await client.get("/api/v2/cmdb/router/static", {**v, "format": "seq-num|dst|device"}))
    ifaces = results(
        await client.get("/api/v2/cmdb/system/interface", {**v, "format": "name|type|ip|mode|vlanid"})
    )
    used_ifaces = [i["name"] for i in ifaces if isinstance(i, dict) and _in_use(i)] if isinstance(ifaces, list) else []

    def entry(kind: str, used: int, items: list[Any]) -> dict[str, Any]:
        limit = EVAL_LIMITS[kind] if is_eval else None
        out: dict[str, Any] = {"used": used, "limit": limit, "items": items}
        if limit is not None:
            out["free"] = max(limit - used, 0)
        return out

    return {
        "license": vm.get("status"),
        "evaluation_limits_apply": is_eval,
        "cpu": {"used": vm.get("cpu_used"), "max": vm.get("cpu_max")},
        "memory_mb": {
            "used": (vm.get("mem_used") or 0) // 2**20 or None,
            "max": (vm.get("mem_max") or 0) // 2**20 or None,
        },
        "policies": entry(
            "policies",
            len(policies) if isinstance(policies, list) else 0,
            [f"{p.get('policyid')}:{p.get('name')}" for p in policies] if isinstance(policies, list) else [],
        ),
        "static_routes": entry(
            "static_routes",
            len(routes) if isinstance(routes, list) else 0,
            [f"{r.get('seq-num')}:{r.get('dst')} via {r.get('device')}" for r in routes] if isinstance(routes, list) else [],
        ),
        "interfaces": entry("interfaces", len(used_ifaces), used_ifaces),
    }


async def free_policy_slots(client: FortiGateClient, v: dict[str, Any]) -> int | None:
    """Free policy slots under the evaluation license, or None when no limit applies."""
    cap = await capacity(client, v)
    return cap["policies"].get("free") if cap["evaluation_limits_apply"] else None
