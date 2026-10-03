"""Live traffic views: FortiView realtime statistics and the ARP table."""

from __future__ import annotations

from typing import Any

from ..client import FortiGateClient
from ..integrations import pve
from ._common import BOOL, INT, STR, compact, results, schema, vdom_param

REPORT_BY = ("source", "destination", "application", "country", "interface", "policy", "protocol")
SORT_BY = ("bytes", "sessions", "bandwidth", "packets")

TOOLS = [
    {
        "name": "get_top_traffic",
        "description": (
            "Live FortiView summary of the sessions passing through right now, grouped by source, "
            "destination, application, country, interface, policy or protocol. Destinations include "
            "the resolved hostname; application IDs are translated to names. Empty when nothing "
            "is flowing (it reflects current sessions, not history)."
        ),
        "inputSchema": schema(
            {
                "report_by": STR("source, destination (default), application, country, interface, policy or protocol"),
                "sort_by": STR("bytes (default), sessions, bandwidth or packets"),
                "count": INT("Rows to return (default 10)"),
                "srcaddr": STR("Only sessions from this IP"),
                "dstaddr": STR("Only sessions to this IP"),
                "policyid": INT("Only sessions matched by this policy"),
                "resolve_vms": BOOL("Label IPs/MACs with the Proxmox VM that owns them (needs PROXMOX_*)"),
            }
        ),
    },
    {
        "name": "get_arp_table",
        "description": "IPv4 ARP table: which MAC answers for which IP on each interface.",
        "inputSchema": schema({"interface": STR("Only this interface, e.g. port2")}),
    },
]

_app_names: dict[int, str] = {}


async def app_names(client: FortiGateClient, ids: set[int], v: dict[str, Any]) -> dict[int, str]:
    """Resolve application signature IDs to names, caching across calls."""
    for app_id in ids - _app_names.keys():
        found = results(await client.get("/api/v2/cmdb/application/name", {**v, "filter": f"id=={app_id}", "format": "id|name"}))
        _app_names[app_id] = found[0]["name"] if isinstance(found, list) and found else str(app_id)
    return {i: _app_names[i] for i in ids}


def _filter(value: Any) -> str:
    # FortiView filters take a JSON-ish {"value": ...} object per field.
    return f'{{"value":"{value}"}}'


async def handle(name: str, args: dict[str, Any], client: FortiGateClient) -> Any:
    v = vdom_param(args)

    if name == "get_top_traffic":
        report_by = args.get("report_by", "destination")
        sort_by = args.get("sort_by", "bytes")
        if report_by not in REPORT_BY:
            raise ValueError(f"report_by must be one of {', '.join(REPORT_BY)}")
        if sort_by not in SORT_BY:
            raise ValueError(f"sort_by must be one of {', '.join(SORT_BY)}")
        params: dict[str, Any] = {**v, "report_by": report_by, "sort_by": sort_by, "count": args.get("count", 10)}
        for key in ("srcaddr", "dstaddr", "policyid"):
            if args.get(key) is not None:
                params[key] = _filter(args[key])
        res = results(await client.get("/api/v2/monitor/fortiview/realtime-statistics", params))
        rows = res.get("details", []) if isinstance(res, dict) else res
        if not isinstance(rows, list):
            return res
        ids = {a["id"] for r in rows for a in r.get("apps") or [] if isinstance(a.get("id"), int)}
        names = await app_names(client, ids, v) if ids else {}
        out = []
        for r in rows:
            row = {k: r.get(k) for k in (
                "srcaddr", "dstaddr", "resolved", "country", "dst_port", "srcintf", "dstintf",
                "sessions", "sentbyte", "rcvdbyte", "tx_bandwidth", "rx_bandwidth", "policyid",
            ) if r.get(k) not in (None, "")}
            if r.get("apps"):
                row["applications"] = [names.get(a.get("id"), a.get("id")) for a in r["apps"]]
            out.append(row)
        if args.get("resolve_vms"):
            out = await pve.annotate(out, client, v)
        return out

    elif name == "get_arp_table":
        arp = results(await client.get("/api/v2/monitor/network/arp", v))
        if isinstance(arp, list) and args.get("interface"):
            arp = [a for a in arp if a.get("interface") == args["interface"]]
        return compact(arp)

    raise ValueError(f"Unknown tool: {name}")
