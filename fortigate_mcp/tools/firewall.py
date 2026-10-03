"""Firewall tools: policies, addresses, address groups, custom services, hit counts, sessions."""

from __future__ import annotations

from typing import Any

from ..client import FortiGateClient
from ._common import (
    BOOL,
    EXTRA,
    INT,
    LIST_PROPS,
    STR,
    STR_LIST,
    body,
    list_params,
    mkey,
    names,
    one,
    results,
    schema,
    subnet,
    vdom_param,
    write_result,
)

POLICY = "/api/v2/cmdb/firewall/policy"
ADDRESS = "/api/v2/cmdb/firewall/address"
ADDRGRP = "/api/v2/cmdb/firewall/addrgrp"
SERVICE = "/api/v2/cmdb/firewall.service/custom"
SERVICE_GROUP = "/api/v2/cmdb/firewall.service/group"

POLICY_FIELDS = {
    "name": STR("Policy name"),
    "srcintf": STR_LIST("Source interfaces, e.g. [port2]"),
    "dstintf": STR_LIST("Destination interfaces, e.g. [port1]"),
    "srcaddr": STR_LIST("Source addresses or groups, e.g. [LAB-NET] or [all]"),
    "dstaddr": STR_LIST("Destination addresses or groups"),
    "service": STR_LIST("Services, e.g. [HTTP, HTTPS] or [ALL]"),
    "action": STR("accept or deny"),
    "schedule": STR("Schedule (default always)"),
    "nat": BOOL("Source NAT to the outgoing interface IP"),
    "logtraffic": STR("all, utm or disable"),
    "status": STR("enable or disable"),
    "comments": STR("Comment"),
    "ssl_ssh_profile": STR(
        "SSL/SSH inspection profile: no-inspection, certificate-inspection (hostname/cert visibility, "
        "no decryption) or deep-inspection / a custom profile (decrypts; clients must trust the CA)"
    ),
    "application_list": STR("Application control profile, e.g. default ('' to detach)"),
    "ips_sensor": STR("IPS sensor ('' to detach)"),
    "av_profile": STR("Antivirus profile ('' to detach)"),
    "webfilter_profile": STR("Web filter profile ('' to detach)"),
    "utm_status": BOOL(
        "Enable security profiles on the policy. Turned on automatically when a profile is given"
    ),
    "extra": EXTRA,
}
SECURITY_PROFILES = {
    "application_list": "application-list",
    "ips_sensor": "ips-sensor",
    "av_profile": "av-profile",
    "webfilter_profile": "webfilter-profile",
}
POLICY_MAP = {
    "name": "name", "srcintf": "srcintf", "dstintf": "dstintf", "srcaddr": "srcaddr",
    "dstaddr": "dstaddr", "service": "service", "action": "action", "schedule": "schedule",
    "logtraffic": "logtraffic", "status": "status", "comments": "comments",
    "ssl_ssh_profile": "ssl-ssh-profile", **SECURITY_PROFILES,
}
POLICY_LISTS = ("srcintf", "dstintf", "srcaddr", "dstaddr", "service")

ADDRESS_FIELDS = {
    "name": STR("Address name"),
    "subnet": STR("Subnet in CIDR (10.0.0.0/24) or 'ip mask' form; a host is /32"),
    "start_ip": STR("Range start (use with end_ip instead of subnet)"),
    "end_ip": STR("Range end"),
    "fqdn": STR("FQDN (instead of subnet or range)"),
    "comment": STR("Comment"),
    "extra": EXTRA,
}

TOOLS = [
    {
        "name": "list_firewall_policies",
        "description": "List IPv4 firewall policies in evaluation order.",
        "inputSchema": schema({**LIST_PROPS}),
    },
    {
        "name": "get_firewall_policy",
        "description": "Get one firewall policy.",
        "inputSchema": schema({"policyid": INT("Policy ID")}, ["policyid"]),
    },
    {
        "name": "create_firewall_policy",
        "description": (
            "Create a firewall policy. New policies are added at the end of the list; use "
            "move_firewall_policy to reorder. FortiGate-VM evaluation licenses allow only 3 policies."
        ),
        "inputSchema": schema(
            {"policyid": INT("Policy ID (optional; FortiOS picks the next free ID)"), **POLICY_FIELDS},
            ["name", "srcintf", "dstintf", "srcaddr", "dstaddr", "service"],
        ),
    },
    {
        "name": "update_firewall_policy",
        "description": "Update a firewall policy. Only the fields given change; list fields are replaced, not appended.",
        "inputSchema": schema({"policyid": INT("Policy ID"), **POLICY_FIELDS}, ["policyid"]),
    },
    {
        "name": "delete_firewall_policy",
        "description": "Delete a firewall policy.",
        "inputSchema": schema({"policyid": INT("Policy ID")}, ["policyid"]),
    },
    {
        "name": "move_firewall_policy",
        "description": "Move a policy before or after another one (policies match top-down).",
        "inputSchema": schema(
            {
                "policyid": INT("Policy ID to move"),
                "before": INT("Place it before this policy ID"),
                "after": INT("Place it after this policy ID"),
            },
            ["policyid"],
        ),
    },
    {
        "name": "get_policy_stats",
        "description": "Hit counts, bytes, packets and last-used time per policy.",
        "inputSchema": schema({"policyid": INT("Limit to one policy (optional)")}),
    },
    {
        "name": "list_sessions",
        "description": "Current firewall sessions, optionally filtered.",
        "inputSchema": schema(
            {
                "count": INT("Maximum sessions to return (default 50)"),
                "srcaddr": STR("Filter by source IP"),
                "dstaddr": STR("Filter by destination IP"),
                "dstport": INT("Filter by destination port"),
                "policyid": INT("Filter by policy ID"),
            }
        ),
    },
    {
        "name": "list_addresses",
        "description": "List firewall address objects.",
        "inputSchema": schema({**LIST_PROPS}),
    },
    {
        "name": "get_address",
        "description": "Get one firewall address object.",
        "inputSchema": schema({"name": STR("Address name")}, ["name"]),
    },
    {
        "name": "create_address",
        "description": "Create a firewall address: a subnet/host, an IP range, or an FQDN.",
        "inputSchema": schema(ADDRESS_FIELDS, ["name"]),
    },
    {
        "name": "update_address",
        "description": "Update a firewall address object.",
        "inputSchema": schema(ADDRESS_FIELDS, ["name"]),
    },
    {
        "name": "delete_address",
        "description": "Delete a firewall address (fails while a policy or group still uses it).",
        "inputSchema": schema({"name": STR("Address name")}, ["name"]),
    },
    {
        "name": "list_address_groups",
        "description": "List firewall address groups and their members.",
        "inputSchema": schema({**LIST_PROPS}),
    },
    {
        "name": "create_address_group",
        "description": "Create an address group.",
        "inputSchema": schema(
            {"name": STR("Group name"), "members": STR_LIST("Member address names"),
             "comment": STR("Comment"), "extra": EXTRA},
            ["name", "members"],
        ),
    },
    {
        "name": "update_address_group",
        "description": "Update an address group. members replaces the whole member list.",
        "inputSchema": schema(
            {"name": STR("Group name"), "members": STR_LIST("Complete new member list"),
             "comment": STR("Comment"), "extra": EXTRA},
            ["name"],
        ),
    },
    {
        "name": "delete_address_group",
        "description": "Delete an address group (fails while a policy still uses it).",
        "inputSchema": schema({"name": STR("Group name")}, ["name"]),
    },
    {
        "name": "list_services",
        "description": "List custom firewall services (port definitions).",
        "inputSchema": schema({**LIST_PROPS}),
    },
    {
        "name": "create_service",
        "description": "Create a custom TCP/UDP service.",
        "inputSchema": schema(
            {
                "name": STR("Service name"),
                "tcp_portrange": STR("TCP ports, e.g. '6443' or '8000-8080 9000'"),
                "udp_portrange": STR("UDP ports"),
                "comment": STR("Comment"),
                "extra": EXTRA,
            },
            ["name"],
        ),
    },
    {
        "name": "list_service_groups",
        "description": "List service groups and their members.",
        "inputSchema": schema({**LIST_PROPS}),
    },
    {
        "name": "create_service_group",
        "description": (
            "Create a service group, e.g. K3S-MGMT = [SSH, K8S-API, PING]. Grouping services lets one "
            "policy cover what would otherwise need several, which helps under the evaluation "
            "license's 3-policy limit."
        ),
        "inputSchema": schema(
            {"name": STR("Group name"), "members": STR_LIST("Service or group names"),
             "comment": STR("Comment"), "extra": EXTRA},
            ["name", "members"],
        ),
    },
    {
        "name": "update_service_group",
        "description": "Update a service group. members replaces the whole member list.",
        "inputSchema": schema(
            {"name": STR("Group name"), "members": STR_LIST("Complete new member list"),
             "comment": STR("Comment"), "extra": EXTRA},
            ["name"],
        ),
    },
    {
        "name": "delete_service_group",
        "description": "Delete a service group (fails while a policy still uses it).",
        "inputSchema": schema({"name": STR("Group name")}, ["name"]),
    },
    {
        "name": "delete_service",
        "description": "Delete a custom service (fails while a policy still uses it).",
        "inputSchema": schema({"name": STR("Service name")}, ["name"]),
    },
]

def _address_body(args: dict[str, Any]) -> dict[str, Any]:
    data = body(args, {"name": "name", "comment": "comment", "fqdn": "fqdn"})
    if args.get("subnet"):
        data["subnet"] = subnet(args["subnet"])
    if args.get("start_ip") or args.get("end_ip"):
        data.update({"type": "iprange", "start-ip": args.get("start_ip"), "end-ip": args.get("end_ip")})
    if args.get("fqdn"):
        data["type"] = "fqdn"
    return data


def _policy_body(args: dict[str, Any]) -> dict[str, Any]:
    data = body(args, POLICY_MAP, POLICY_LISTS)
    if "nat" in args and args["nat"] is not None:
        data["nat"] = "enable" if args["nat"] else "disable"
    if args.get("utm_status") is not None:
        data["utm-status"] = "enable" if args["utm_status"] else "disable"
    elif any(args.get(arg) for arg in SECURITY_PROFILES):
        data["utm-status"] = "enable"
    return data


async def _inspection_warning(client: FortiGateClient, policyid: Any, v: dict[str, Any]) -> str | None:
    """Flag the flow-mode trap: an SSL profile on a policy without any security profile does nothing."""
    policy = one(await client.get(f"{POLICY}/{policyid}", v))
    if not isinstance(policy, dict):
        return None
    ssl = policy.get("ssl-ssh-profile") or "no-inspection"
    has_profile = policy.get("utm-status") == "enable" and any(
        policy.get(attr) for attr in SECURITY_PROFILES.values()
    )
    if ssl != "no-inspection" and not has_profile:
        return (
            f"ssl-ssh-profile {ssl!r} has no effect: in flow mode traffic is only inspected when a "
            "security profile is attached (e.g. application_list='default')."
        )
    return None


async def handle(name: str, args: dict[str, Any], client: FortiGateClient) -> Any:
    v = vdom_param(args)

    if name == "list_firewall_policies":
        return results(await client.get(POLICY, list_params(args)))

    elif name == "get_firewall_policy":
        return one(await client.get(f"{POLICY}/{args['policyid']}", v))

    elif name == "create_firewall_policy":
        data = {"action": "accept", "schedule": "always", **_policy_body(args)}
        if args.get("policyid"):
            data["policyid"] = args["policyid"]
        out = write_result(await client.post(POLICY, data, v))
        if args.get("ssl_ssh_profile") and isinstance(out, dict) and out.get("mkey") is not None:
            if warning := await _inspection_warning(client, out["mkey"], v):
                out["warning"] = warning
        return out

    elif name == "update_firewall_policy":
        out = write_result(await client.put(f"{POLICY}/{args['policyid']}", _policy_body(args), v))
        touched = ("ssl_ssh_profile", "utm_status", *SECURITY_PROFILES)
        if any(k in args for k in touched) and isinstance(out, dict):
            if warning := await _inspection_warning(client, args["policyid"], v):
                out["warning"] = warning
        return out

    elif name == "delete_firewall_policy":
        return write_result(await client.delete(f"{POLICY}/{args['policyid']}", v))

    elif name == "move_firewall_policy":
        if bool(args.get("before")) == bool(args.get("after")):
            raise ValueError("Give exactly one of before or after")
        where = "before" if args.get("before") else "after"
        params = {**v, "action": "move", where: args[where]}
        return write_result(await client.put(f"{POLICY}/{args['policyid']}", None, params))

    elif name == "get_policy_stats":
        params = {**v, "policyid": args.get("policyid")}
        stats = results(await client.get("/api/v2/monitor/firewall/policy", params))
        keep = ("policyid", "hit_count", "bytes", "packets", "active_sessions", "last_used", "first_used")
        if isinstance(stats, list):
            return [{k: s.get(k) for k in keep} for s in stats]
        return stats

    elif name == "list_sessions":
        params: dict[str, Any] = {**v, "count": args.get("count", 50), "start": 0}
        for key in ("srcaddr", "dstaddr", "dstport", "policyid"):
            if args.get(key) is not None:
                params[key] = args[key]
        # 7.6 renamed this endpoint to the plural form and nests rows under "details".
        res = results(await client.get("/api/v2/monitor/firewall/sessions", params))
        return res.get("details", res) if isinstance(res, dict) else res

    elif name == "list_addresses":
        return results(await client.get(ADDRESS, list_params(args)))

    elif name == "get_address":
        return one(await client.get(f"{ADDRESS}/{mkey(args['name'])}", v))

    elif name == "create_address":
        return write_result(await client.post(ADDRESS, _address_body(args), v))

    elif name == "update_address":
        data = _address_body(args)
        data.pop("name", None)
        return write_result(await client.put(f"{ADDRESS}/{mkey(args['name'])}", data, v))

    elif name == "delete_address":
        return write_result(await client.delete(f"{ADDRESS}/{mkey(args['name'])}", v))

    elif name == "list_address_groups":
        return results(await client.get(ADDRGRP, list_params(args)))

    elif name == "create_address_group":
        data = {"name": args["name"], "member": names(args["members"]), **body(args, {"comment": "comment"})}
        return write_result(await client.post(ADDRGRP, data, v))

    elif name == "update_address_group":
        data = body(args, {"comment": "comment"})
        if args.get("members") is not None:
            data["member"] = names(args["members"])
        return write_result(await client.put(f"{ADDRGRP}/{mkey(args['name'])}", data, v))

    elif name == "delete_address_group":
        return write_result(await client.delete(f"{ADDRGRP}/{mkey(args['name'])}", v))

    elif name == "list_services":
        return results(await client.get(SERVICE, list_params(args)))

    elif name == "create_service":
        data = body(
            args,
            {"name": "name", "tcp_portrange": "tcp-portrange", "udp_portrange": "udp-portrange",
             "comment": "comment"},
        )
        return write_result(await client.post(SERVICE, data, v))

    elif name == "list_service_groups":
        return results(await client.get(SERVICE_GROUP, list_params(args)))

    elif name == "create_service_group":
        data = {"name": args["name"], "member": names(args["members"]), **body(args, {"comment": "comment"})}
        return write_result(await client.post(SERVICE_GROUP, data, v))

    elif name == "update_service_group":
        data = body(args, {"comment": "comment"})
        if args.get("members") is not None:
            data["member"] = names(args["members"])
        return write_result(await client.put(f"{SERVICE_GROUP}/{mkey(args['name'])}", data, v))

    elif name == "delete_service_group":
        return write_result(await client.delete(f"{SERVICE_GROUP}/{mkey(args['name'])}", v))

    elif name == "delete_service":
        return write_result(await client.delete(f"{SERVICE}/{mkey(args['name'])}", v))

    raise ValueError(f"Unknown tool: {name}")
