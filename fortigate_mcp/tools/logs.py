"""Log tools: read traffic, security and event logs from memory, disk or FortiAnalyzer."""

from __future__ import annotations

import re
from typing import Any

from ..client import FortiGateClient
from ..integrations import pve
from . import _logtargets as logtargets
from ._common import BOOL, INT, STR, STR_LIST, compact, schema, vdom_param

LOG_TYPES = (
    "traffic/forward", "traffic/local", "traffic/multicast", "traffic/sniffer",
    "event/system", "event/user", "event/router", "event/vpn", "event/wad", "event/endpoint",
    "event/ha", "event/security-rating", "event/fortiextender", "event/connector",
    "app-ctrl", "ips", "virus", "webfilter", "dns", "ssl", "ssh", "file-filter",
    "anomaly", "waf", "emailfilter", "dlp", "voip", "gtp", "icap", "virtual-patch",
)
LOG_SOURCES = ("memory", "disk", "fortianalyzer", "forticloud")

FILTER_DESC = (
    "FortiOS log filter, e.g. srcip==192.168.150.10 or hostname=@github. A comma ORs values of "
    "one field (dstport==4332,dstport==4432); pass a list to AND terms ([srcip==10.0.0.5, dstport==443])."
)
TERM = re.compile(r"^\s*([\w-]+)\s*(==|!=|=@|!@|>=|<=|=|>|<)\s*(.*?)\s*$")


def _field(term: str) -> str:
    m = TERM.match(term)
    if not m:
        raise ValueError(f"Can't parse log filter term {term!r}; use field==value, field=@text and so on")
    return m.group(1)


def _filters(log_type: str, raw: Any) -> list[str]:
    """Validate the filter and return its AND clauses, each sent as its own filter parameter.

    FortiOS silently ignores a filter it cannot apply and returns unfiltered rows, so the two
    forms it drops (an '&' inside one filter, a comma OR across different fields) are refused.
    """
    clauses = [raw] if isinstance(raw, str) else list(raw or [])
    clauses = [c.strip() for c in clauses if c and c.strip()]
    for clause in clauses:
        if "&" in clause:
            raise ValueError("FortiOS ignores a filter containing '&'; pass AND terms as a list instead")
        fields = {_field(t) for t in clause.split(",")}
        if len(fields) > 1:
            raise ValueError(
                f"FortiOS ignores a comma OR across different fields ({', '.join(sorted(fields))}) and "
                "returns unfiltered rows; OR values of one field only, and make one call per field"
            )
    # event/<subtype> endpoints are not scoped to their subtype: with no matching rows FortiOS
    # stops part-way through the event log and returns other subtypes' rows instead.
    category, _, sub = log_type.partition("/")
    if category == "event" and not any(_field(c.split(",")[0]) == "subtype" for c in clauses):
        clauses.insert(0, f"subtype=={sub}")
    return clauses


def _matches(row: dict[str, Any], clause: str) -> bool | None:
    """Whether a row satisfies an all-'==' clause; None when the clause uses other operators."""
    terms = [TERM.match(t) for t in clause.split(",")]
    if any(m is None or m.group(2) != "==" for m in terms):
        return None
    for m in terms:
        field, want = m.group(1), m.group(3).strip('"')
        have = str(row.get(field))
        if have == want or (field == "logid" and want.isdigit() and have.endswith(want.lstrip("0"))):
            return True
    return False

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
                "filter": {"anyOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}],
                           "description": FILTER_DESC},
                "resolve_vms": BOOL("Label IPs/MACs with the Proxmox VM that owns them (needs PROXMOX_*)"),
                "fields": STR_LIST(
                    "Only return these fields per row, e.g. [date, time, srcip, dstip, hostname, app, action]"
                ),
            },
            ["log_type"],
        ),
    },
]
TOOLS += logtargets.TOOLS


async def handle(name: str, args: dict[str, Any], client: FortiGateClient) -> Any:
    if name in {t["name"] for t in logtargets.TOOLS}:
        return await logtargets.handle(name, args, client)
    if name == "get_logs":
        log_type = args["log_type"].strip("/")
        if log_type not in LOG_TYPES:
            raise ValueError(f"Unknown log_type {log_type!r}; use one of: {', '.join(LOG_TYPES)}")
        source = args.get("source", "memory")
        if source not in LOG_SOURCES:
            raise ValueError(f"Unknown source {source!r}; use one of: {', '.join(LOG_SOURCES)}")
        clauses = _filters(log_type, args.get("filter"))
        params = {
            **vdom_param(args),
            "rows": min(int(args.get("rows", 50)), 1000),
            "start": args.get("start", 0),
            "filter": clauses or None,
        }
        resp = await client.get(f"/api/v2/log/{source}/{log_type}", params)
        rows = resp.get("results", []) if isinstance(resp, dict) else resp
        if not isinstance(rows, list):
            return compact(resp)
        # Logs carry internal _metadata and *_raw_value duplicates; drop them for readability.
        rows = [{k: v for k, v in r.items() if k != "_metadata" and not k.endswith("_raw_value")} for r in rows]
        warnings = []
        # Guard against FortiOS ignoring a filter in some way not caught above: check exact terms.
        kept = [r for r in rows if all(_matches(r, c) is not False for c in clauses)]
        if len(kept) < len(rows):
            warnings.append(
                f"FortiOS returned {len(rows) - len(kept)} rows that don't match the filter; they were "
                "dropped here, so matches beyond this page may be missing"
            )
            rows = kept
        done = resp.get("percent_logs_processed") if isinstance(resp, dict) else None
        if isinstance(done, int) and done < 100:
            warnings.append(f"FortiOS searched only {done}% of the log, so results may be incomplete")
        if args.get("resolve_vms"):
            rows = await pve.annotate(rows, client, vdom_param(args))
        if args.get("fields"):
            fields = args["fields"]
            rows = [
                {f: r.get(f) for f in fields} | {f"{f}_vm": r[f"{f}_vm"] for f in fields if f"{f}_vm" in r}
                for r in rows
            ]
        out: dict[str, Any] = {"rows": len(rows), "results": rows}
        if isinstance(resp, dict) and "total_lines" in resp:
            out["total_lines"] = resp["total_lines"]
        if warnings:
            out["warnings"] = warnings
        return out

    raise ValueError(f"Unknown tool: {name}")
