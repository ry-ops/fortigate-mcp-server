"""Log tools: read traffic, security and event logs from memory, disk or FortiAnalyzer."""

from __future__ import annotations

from typing import Any

from ..client import FortiGateClient
from ._common import INT, STR, STR_LIST, compact, schema, vdom_param

LOG_TYPES = (
    "traffic/forward", "traffic/local", "traffic/multicast", "traffic/sniffer",
    "event/system", "event/user", "event/router", "event/vpn", "event/wad", "event/endpoint",
    "event/ha", "event/security-rating", "event/fortiextender", "event/connector",
    "app-ctrl", "ips", "virus", "webfilter", "dns", "ssl", "ssh", "file-filter",
    "anomaly", "waf", "emailfilter", "dlp", "voip", "gtp", "icap", "virtual-patch",
)
LOG_SOURCES = ("memory", "disk", "fortianalyzer", "forticloud")

TOOLS = [
    {
        "name": "get_logs",
        "description": (
            "Read FortiGate logs, newest first. Useful types: traffic/forward (sessions through "
            "policies, with app identification), app-ctrl (per-connection application and, with "
            "certificate inspection, the HTTPS hostname), event/system (admin and config events), "
            "ips, webfilter. FortiGate-VMs without a log disk only keep logs in memory, which is "
            "lost on reboot."
        ),
        "inputSchema": schema(
            {
                "log_type": STR("One of: " + ", ".join(LOG_TYPES)),
                "source": STR("memory (default), disk, fortianalyzer or forticloud"),
                "rows": INT("Rows to return (default 50, max 1000)"),
                "start": INT("Offset for paging (default 0)"),
                "filter": STR("FortiOS log filter, e.g. srcip==192.168.150.10 or policyid==1 or hostname=@github"),
                "fields": STR_LIST(
                    "Only return these fields per row, e.g. [date, time, srcip, dstip, hostname, app, action]"
                ),
            },
            ["log_type"],
        ),
    },
]


async def handle(name: str, args: dict[str, Any], client: FortiGateClient) -> Any:
    if name == "get_logs":
        log_type = args["log_type"].strip("/")
        if log_type not in LOG_TYPES:
            raise ValueError(f"Unknown log_type {log_type!r}; use one of: {', '.join(LOG_TYPES)}")
        source = args.get("source", "memory")
        if source not in LOG_SOURCES:
            raise ValueError(f"Unknown source {source!r}; use one of: {', '.join(LOG_SOURCES)}")
        params = {
            **vdom_param(args),
            "rows": min(int(args.get("rows", 50)), 1000),
            "start": args.get("start", 0),
            "filter": args.get("filter"),
        }
        resp = await client.get(f"/api/v2/log/{source}/{log_type}", params)
        rows = resp.get("results", []) if isinstance(resp, dict) else resp
        if not isinstance(rows, list):
            return compact(resp)
        # Logs carry internal _metadata and *_raw_value duplicates; drop them for readability.
        rows = [{k: v for k, v in r.items() if k != "_metadata" and not k.endswith("_raw_value")} for r in rows]
        if args.get("fields"):
            rows = [{f: r.get(f) for f in args["fields"]} for r in rows]
        out: dict[str, Any] = {"rows": len(rows), "results": rows}
        if isinstance(resp, dict) and "total_lines" in resp:
            out["total_lines"] = resp["total_lines"]
        return out

    raise ValueError(f"Unknown tool: {name}")
