"""Escape hatch: call any FortiOS REST endpoint the other tools don't model yet."""

from __future__ import annotations

from typing import Any

from ..client import FortiGateClient
from ._common import OBJ, STR, compact, schema

TOOLS = [
    {
        "name": "fortigate_api",
        "description": (
            "Call any FortiOS REST endpoint directly. path must start with /api/v2/ "
            "(cmdb/... for configuration, monitor/... for live state). FORTIGATE_READ_ONLY still "
            "applies. Prefer the dedicated tools when one exists."
        ),
        "inputSchema": schema(
            {
                "method": STR("GET, POST, PUT or DELETE"),
                "path": STR("e.g. /api/v2/cmdb/system/global or /api/v2/monitor/system/ha-peer"),
                "params": OBJ("Query parameters"),
                "body": OBJ("JSON body for POST/PUT"),
            },
            ["method", "path"],
        ),
    },
]


async def handle(name: str, args: dict[str, Any], client: FortiGateClient) -> Any:
    if name == "fortigate_api":
        method = args["method"].upper()
        if method not in ("GET", "POST", "PUT", "DELETE"):
            raise ValueError(f"Unsupported method: {method}")
        path = args["path"]
        if not path.startswith("/api/v2/"):
            raise ValueError("path must start with /api/v2/")
        params = {**(args.get("params") or {}), "vdom": args.get("vdom")}
        return compact(await client.request(method, path, params, args.get("body")))

    raise ValueError(f"Unknown tool: {name}")
