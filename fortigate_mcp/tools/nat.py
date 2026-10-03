"""Port forwards (virtual IPs), built to work inside the evaluation license's 3-policy limit."""

from __future__ import annotations

from typing import Any

from ..client import FortiGateClient
from ._capacity import free_policy_slots
from ._common import (
    BOOL,
    EXTRA,
    INT,
    LIST_PROPS,
    STR,
    list_params,
    mkey,
    names,
    one,
    results,
    schema,
    vdom_param,
    write_result,
)

VIP = "/api/v2/cmdb/firewall/vip"
POLICY = "/api/v2/cmdb/firewall/policy"

TOOLS = [
    {
        "name": "list_port_forwards",
        "description": "List virtual IPs (port forwards / static NAT) and the policies that use each one.",
        "inputSchema": schema({**LIST_PROPS}),
    },
    {
        "name": "create_port_forward",
        "description": (
            "Create a port forward (VIP): traffic arriving on extintf at extip:extport goes to "
            "mappedip:mappedport. A VIP only passes traffic once a policy from extintf uses it as a "
            "destination. With attach_to_policy, the VIP is added to that existing policy's "
            "destinations instead of needing a new policy (the evaluation license allows only 3). "
            "FortiOS does not allow VIPs and ordinary addresses in the same policy's destinations, "
            "so the target must already use only VIPs, or pass replace_destinations=true to turn it "
            "into a VIP-only policy (its old destinations stop being reachable through it). In that "
            "policy, services match the mapped (internal) port."
        ),
        "inputSchema": schema(
            {
                "name": STR("VIP name, e.g. VIP-TRAEFIK-HTTPS"),
                "extintf": STR("Interface the traffic arrives on, e.g. port1"),
                "extip": STR("External IP (default 0.0.0.0 = the extintf's own address)"),
                "mappedip": STR("Internal IP or range a-b, e.g. 192.168.150.10 or 192.168.150.10-192.168.150.12"),
                "protocol": STR("tcp (default), udp or sctp"),
                "extport": STR("External port or range, e.g. 8443"),
                "mappedport": STR("Internal port or range (default: same as extport)"),
                "attach_to_policy": INT("Add this VIP to an existing policy's destinations (recommended)"),
                "replace_destinations": BOOL(
                    "With attach_to_policy: replace the policy's ordinary-address destinations with this VIP"
                ),
                "comment": STR("Comment"),
                "extra": EXTRA,
            },
            ["name", "extintf", "mappedip", "extport"],
        ),
    },
    {
        "name": "delete_port_forward",
        "description": (
            "Delete a VIP. FortiOS refuses while a policy uses it; detach=true first removes it from "
            "every policy's destinations. A policy whose only destination is this VIP blocks the "
            "delete: change or delete that policy first."
        ),
        "inputSchema": schema(
            {"name": STR("VIP name"), "detach": BOOL("Remove the VIP from policies first (default false)")},
            ["name"],
        ),
    },
]


async def _policies_using(client: FortiGateClient, vip: str, v: dict[str, Any]) -> list[dict[str, Any]]:
    pols = results(await client.get(POLICY, {**v, "format": "policyid|name|dstaddr"}))
    if not isinstance(pols, list):
        return []
    return [p for p in pols if any(d.get("name") == vip for d in p.get("dstaddr") or [])]


async def _vip_names(client: FortiGateClient, v: dict[str, Any]) -> set[str]:
    found: set[str] = set()
    for path in (VIP, "/api/v2/cmdb/firewall/vipgrp"):
        items = results(await client.get(path, {**v, "format": "name"}))
        if isinstance(items, list):
            found |= {i["name"] for i in items}
    return found


async def handle(name: str, args: dict[str, Any], client: FortiGateClient) -> Any:
    v = vdom_param(args)

    if name == "list_port_forwards":
        vips = results(await client.get(VIP, list_params(args)))
        if not isinstance(vips, list) or args.get("format"):
            return vips
        pols = results(await client.get(POLICY, {**v, "format": "policyid|name|dstaddr"}))
        pols = pols if isinstance(pols, list) else []
        out = []
        for x in vips:
            out.append(
                {
                    "name": x.get("name"),
                    "type": x.get("type"),
                    "extintf": x.get("extintf"),
                    "extip": x.get("extip"),
                    "mappedip": [m.get("range") for m in x.get("mappedip") or []],
                    "portforward": x.get("portforward"),
                    "protocol": x.get("protocol"),
                    "extport": x.get("extport"),
                    "mappedport": x.get("mappedport"),
                    "comment": x.get("comment"),
                    "used_by_policies": [
                        f"{p['policyid']}:{p.get('name')}"
                        for p in pols
                        if any(d.get("name") == x.get("name") for d in p.get("dstaddr") or [])
                    ],
                }
            )
        return out

    elif name == "create_port_forward":
        policyid = args.get("attach_to_policy")
        target: dict[str, Any] | None = None
        keep: list[str] = []
        if policyid is not None:
            target = one(await client.get(f"{POLICY}/{policyid}", v))
            if not isinstance(target, dict) or not target.get("policyid"):
                raise ValueError(f"Policy {policyid} not found")
            if not any(i.get("name") == args["extintf"] for i in target.get("srcintf") or []):
                raise ValueError(
                    f"Policy {policyid} does not take traffic from {args['extintf']}; a VIP must be "
                    "attached to a policy whose source interface is the VIP's extintf"
                )
            vips = await _vip_names(client, v)
            current = [d["name"] for d in target.get("dstaddr") or []]
            plain = [d for d in current if d not in vips]
            if plain and not args.get("replace_destinations"):
                raise ValueError(
                    f"Policy {policyid} has ordinary destinations {plain}, and FortiOS cannot mix them "
                    "with VIPs. Pass replace_destinations=true to make it a VIP-only policy (those "
                    "destinations stop being reachable through it), or attach to a VIP-only policy."
                )
            keep = [d for d in current if d in vips]

        data: dict[str, Any] = {
            "name": args["name"],
            "type": "static-nat",
            "extintf": args["extintf"],
            "extip": args.get("extip", "0.0.0.0"),
            "mappedip": [{"range": args["mappedip"]}],
            "portforward": "enable",
            "protocol": args.get("protocol", "tcp"),
            "extport": str(args["extport"]),
            "mappedport": str(args.get("mappedport") or args["extport"]),
        }
        if args.get("comment"):
            data["comment"] = args["comment"]
        data.update(args.get("extra") or {})
        out = write_result(await client.post(VIP, data, v))

        if target is not None:
            try:
                await client.put(f"{POLICY}/{policyid}", {"dstaddr": names([*keep, args["name"]])}, v)
            except Exception:
                # Don't leave an orphaned VIP behind when the policy refuses it.
                await client.delete(f"{VIP}/{mkey(args['name'])}", v)
                raise
            out["attached_to_policy"] = policyid
            replaced = [d["name"] for d in target.get("dstaddr") or [] if d["name"] not in keep]
            if replaced:
                out["replaced_destinations"] = replaced
        else:
            free = await free_policy_slots(client, v)
            note = (
                "The VIP passes no traffic until a policy from "
                f"{args['extintf']} lists it as a destination."
            )
            if free == 0:
                note += (
                    " The evaluation license's 3 policies are all in use: re-run with "
                    "attach_to_policy=<a policy from that interface>."
                )
            out["note"] = note
        return out

    elif name == "delete_port_forward":
        users = await _policies_using(client, args["name"], v)
        if users and not args.get("detach"):
            raise ValueError(
                f"VIP {args['name']!r} is used by policies {[p['policyid'] for p in users]}; "
                "set detach=true to remove it from them first"
            )
        detached = []
        for p in users:
            remaining = [d["name"] for d in p.get("dstaddr") or [] if d.get("name") != args["name"]]
            if not remaining:
                raise ValueError(
                    f"Policy {p['policyid']} would be left with no destination; give it another "
                    "destination or delete the policy first"
                )
            await client.put(f"{POLICY}/{p['policyid']}", {"dstaddr": names(remaining)}, v)
            detached.append(p["policyid"])
        out = write_result(await client.delete(f"{VIP}/{mkey(args['name'])}", v))
        if detached:
            out["detached_from_policies"] = detached
        return out

    raise ValueError(f"Unknown tool: {name}")
