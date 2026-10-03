"""DNS service, local DNS zones and DHCP server tools."""

from __future__ import annotations

from typing import Any

from ..client import FortiGateAPIError, FortiGateClient
from ._common import (
    BOOL,
    EXTRA,
    INT,
    LIST_PROPS,
    STR,
    body,
    list_params,
    mkey,
    results,
    schema,
    vdom_param,
    write_result,
)

DNS_SERVER = "/api/v2/cmdb/system/dns-server"
DNS_DB = "/api/v2/cmdb/system/dns-database"
DHCP = "/api/v2/cmdb/system.dhcp/server"

RECORD_SCHEMA = {
    "type": "object",
    "properties": {
        "hostname": {"type": "string"},
        "type": {"type": "string", "description": "A, AAAA, CNAME, MX, NS or PTR (default A)"},
        "ip": {"type": "string"},
        "ipv6": {"type": "string"},
        "canonical_name": {"type": "string", "description": "Target for CNAME records"},
        "ttl": {"type": "integer"},
    },
    "required": ["hostname"],
}

TOOLS = [
    {
        "name": "get_dns_settings",
        "description": "System DNS settings: upstream resolvers the FortiGate itself uses and forwards to.",
        "inputSchema": schema({}),
    },
    {
        "name": "list_dns_servers",
        "description": "Interfaces where the FortiGate answers DNS queries, and in which mode.",
        "inputSchema": schema({}),
    },
    {
        "name": "set_dns_server",
        "description": (
            "Serve DNS on an interface. Modes: recursive (local zones first, then forward to the "
            "system resolvers), non-recursive (local zones only), forward-only."
        ),
        "inputSchema": schema(
            {"interface": STR("Interface, e.g. port2"), "mode": STR("recursive, non-recursive or forward-only")},
            ["interface"],
        ),
    },
    {
        "name": "delete_dns_server",
        "description": "Stop serving DNS on an interface.",
        "inputSchema": schema({"interface": STR("Interface")}, ["interface"]),
    },
    {
        "name": "list_dns_zones",
        "description": "List local DNS zones (dns-database) with their records.",
        "inputSchema": schema({**LIST_PROPS}),
    },
    {
        "name": "create_dns_zone",
        "description": (
            "Create a local DNS zone. view=shadow serves internal clients. FortiOS does not accept "
            "wildcard (*) hostnames, so add one record per name."
        ),
        "inputSchema": schema(
            {
                "name": STR("Zone object name, e.g. lab"),
                "domain": STR("Domain, e.g. lab or lab.home.arpa"),
                "view": STR("shadow (internal, default) or public"),
                "authoritative": BOOL("Answer NXDOMAIN for unknown names in the zone (default true)"),
                "ttl": INT("Default TTL in seconds (default 300)"),
                "records": {"type": "array", "items": RECORD_SCHEMA, "description": "Initial records"},
                "extra": EXTRA,
            },
            ["name", "domain"],
        ),
    },
    {
        "name": "delete_dns_zone",
        "description": "Delete a local DNS zone and all its records.",
        "inputSchema": schema({"name": STR("Zone object name")}, ["name"]),
    },
    {
        "name": "add_dns_record",
        "description": "Add a record to a local DNS zone. Wildcard (*) hostnames are rejected by FortiOS.",
        "inputSchema": schema({"zone": STR("Zone object name"), **RECORD_SCHEMA["properties"]}, ["zone", "hostname"]),
    },
    {
        "name": "delete_dns_record",
        "description": "Delete a record from a local DNS zone by its id (see list_dns_zones).",
        "inputSchema": schema({"zone": STR("Zone object name"), "id": INT("Record id")}, ["zone", "id"]),
    },
    {
        "name": "list_dhcp_servers",
        "description": "List DHCP servers with their ranges, options and reservations.",
        "inputSchema": schema({**LIST_PROPS}),
    },
    {
        "name": "list_dhcp_leases",
        "description": "Current DHCP leases handed out by the FortiGate.",
        "inputSchema": schema({}),
    },
    {
        "name": "update_dhcp_server",
        "description": (
            "Update a DHCP server. Note: vci_match=true makes the server answer only clients whose "
            "vendor class matches vci-string (FortiOS defaults to FortiSwitch/FortiExtender), which "
            "silently ignores ordinary clients."
        ),
        "inputSchema": schema(
            {
                "server_id": INT("DHCP server id"),
                "dns_service": STR("local (hand out the FortiGate itself), default (system DNS) or specify"),
                "domain": STR("Domain name handed to clients"),
                "default_gateway": STR("Gateway handed to clients"),
                "lease_time": INT("Lease time in seconds"),
                "vci_match": BOOL("Only answer clients matching vci-string"),
                "status": STR("enable or disable"),
                "extra": EXTRA,
            },
            ["server_id"],
        ),
    },
    {
        "name": "add_dhcp_reservation",
        "description": "Reserve an IP for a MAC address on a DHCP server (the IP may sit outside the pool).",
        "inputSchema": schema(
            {
                "server_id": INT("DHCP server id"),
                "mac": STR("Client MAC address"),
                "ip": STR("IP to reserve"),
                "description": STR("Description"),
            },
            ["server_id", "mac", "ip"],
        ),
    },
    {
        "name": "delete_dhcp_reservation",
        "description": "Remove a DHCP reservation by its id (see list_dhcp_servers).",
        "inputSchema": schema({"server_id": INT("DHCP server id"), "id": INT("Reservation id")}, ["server_id", "id"]),
    },
]


def _record(rec: dict[str, Any], rec_id: int) -> dict[str, Any]:
    if "*" in rec["hostname"]:
        raise ValueError(
            f"FortiOS rejects wildcard hostnames ({rec['hostname']!r}); add one record per name instead"
        )
    out: dict[str, Any] = {"id": rec_id, "status": "enable", "type": rec.get("type", "A"), "hostname": rec["hostname"]}
    for arg, attr in (("ip", "ip"), ("ipv6", "ipv6"), ("canonical_name", "canonical-name"), ("ttl", "ttl")):
        if rec.get(arg) is not None:
            out[attr] = rec[arg]
    return out


async def _next_id(client: FortiGateClient, path: str, v: dict[str, Any]) -> int:
    existing = results(await client.get(path, v))
    ids = [e.get("id", 0) for e in existing] if isinstance(existing, list) else []
    return max(ids, default=0) + 1


async def handle(name: str, args: dict[str, Any], client: FortiGateClient) -> Any:
    v = vdom_param(args)

    if name == "get_dns_settings":
        return results(await client.get("/api/v2/cmdb/system/dns", v))

    elif name == "list_dns_servers":
        return results(await client.get(DNS_SERVER, v))

    elif name == "set_dns_server":
        data = {"mode": args.get("mode", "recursive")}
        path = f"{DNS_SERVER}/{mkey(args['interface'])}"
        try:
            return write_result(await client.put(path, data, v))
        except FortiGateAPIError as e:
            if e.status != 404:
                raise
            return write_result(await client.post(DNS_SERVER, {"name": args["interface"], **data}, v))

    elif name == "delete_dns_server":
        return write_result(await client.delete(f"{DNS_SERVER}/{mkey(args['interface'])}", v))

    elif name == "list_dns_zones":
        return results(await client.get(DNS_DB, list_params(args)))

    elif name == "create_dns_zone":
        data = {
            "name": args["name"],
            "domain": args["domain"],
            "status": "enable",
            "type": "primary",
            "view": args.get("view", "shadow"),
            "authoritative": "enable" if args.get("authoritative", True) else "disable",
            "ttl": args.get("ttl", 300),
            "dns-entry": [_record(r, i) for i, r in enumerate(args.get("records") or [], start=1)],
        }
        data.update(args.get("extra") or {})
        return write_result(await client.post(DNS_DB, data, v))

    elif name == "delete_dns_zone":
        return write_result(await client.delete(f"{DNS_DB}/{mkey(args['name'])}", v))

    elif name == "add_dns_record":
        path = f"{DNS_DB}/{mkey(args['zone'])}/dns-entry"
        rec = _record(args, 0)  # validate before touching the device
        rec["id"] = await _next_id(client, path, v)
        return write_result(await client.post(path, rec, v))

    elif name == "delete_dns_record":
        return write_result(await client.delete(f"{DNS_DB}/{mkey(args['zone'])}/dns-entry/{args['id']}", v))

    elif name == "list_dhcp_servers":
        return results(await client.get(DHCP, list_params(args)))

    elif name == "list_dhcp_leases":
        return results(await client.get("/api/v2/monitor/system/dhcp", v))

    elif name == "update_dhcp_server":
        data = body(
            args,
            {"dns_service": "dns-service", "domain": "domain", "default_gateway": "default-gateway",
             "lease_time": "lease-time", "status": "status"},
        )
        if args.get("vci_match") is not None:
            data["vci-match"] = "enable" if args["vci_match"] else "disable"
        return write_result(await client.put(f"{DHCP}/{args['server_id']}", data, v))

    elif name == "add_dhcp_reservation":
        path = f"{DHCP}/{args['server_id']}/reserved-address"
        data = {
            "id": await _next_id(client, path, v),
            "type": "mac",
            "mac": args["mac"].lower(),
            # action=assign only means "treat like any client"; the ip field exists only with reserved.
            "action": "reserved",
            "ip": args["ip"],
        }
        if args.get("description"):
            data["description"] = args["description"]
        return write_result(await client.post(path, data, v))

    elif name == "delete_dhcp_reservation":
        return write_result(await client.delete(f"{DHCP}/{args['server_id']}/reserved-address/{args['id']}", v))

    raise ValueError(f"Unknown tool: {name}")
