"""Routing tools: static routes and the live routing table."""

from __future__ import annotations

from typing import Any

from ..client import FortiGateClient
from ._common import (
    EXTRA,
    INT,
    LIST_PROPS,
    STR,
    list_params,
    results,
    schema,
    subnet,
    vdom_param,
    write_result,
)

STATIC = "/api/v2/cmdb/router/static"

TOOLS = [
    {
        "name": "get_routing_table",
        "description": "Active IPv4 routing table (connected, static, DHCP-learned and dynamic routes).",
        "inputSchema": schema({}),
    },
    {
        "name": "list_static_routes",
        "description": "List configured static routes.",
        "inputSchema": schema({**LIST_PROPS}),
    },
    {
        "name": "create_static_route",
        "description": "Add a static route. FortiGate-VM evaluation licenses allow only 3 routes.",
        "inputSchema": schema(
            {
                "dst": STR("Destination in CIDR (10.1.0.0/16) or 'ip mask' form; 0.0.0.0/0 for default"),
                "gateway": STR("Next-hop IP"),
                "device": STR("Outgoing interface, e.g. port1"),
                "distance": INT("Administrative distance (default 10)"),
                "comment": STR("Comment"),
                "extra": EXTRA,
            },
            ["dst", "device"],
        ),
    },
    {
        "name": "delete_static_route",
        "description": "Delete a static route by its sequence number (seq-num from list_static_routes).",
        "inputSchema": schema({"seq_num": INT("Route sequence number")}, ["seq_num"]),
    },
]


async def handle(name: str, args: dict[str, Any], client: FortiGateClient) -> Any:
    v = vdom_param(args)

    if name == "get_routing_table":
        return results(await client.get("/api/v2/monitor/router/ipv4", v))

    elif name == "list_static_routes":
        return results(await client.get(STATIC, list_params(args)))

    elif name == "create_static_route":
        data: dict[str, Any] = {"dst": subnet(args["dst"]), "device": args["device"]}
        for arg, attr in (("gateway", "gateway"), ("distance", "distance"), ("comment", "comment")):
            if args.get(arg) is not None:
                data[attr] = args[arg]
        data.update(args.get("extra") or {})
        return write_result(await client.post(STATIC, data, v))

    elif name == "delete_static_route":
        return write_result(await client.delete(f"{STATIC}/{args['seq_num']}", v))

    raise ValueError(f"Unknown tool: {name}")
