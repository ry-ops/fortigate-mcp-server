"""Kubernetes (k3s) integration: keep FortiGate DNS records and address objects in step with a cluster.

Enabled when K8S_KUBECONFIG is set. The cluster is only read; changes go to the FortiGate, and
both sync tools default to dry_run=true so they show their plan before touching anything.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from ..client import FortiGateAPIError, FortiGateClient
from ..integrations.kube import KubeClient
from ._common import BOOL, STR, mkey, names, one, schema, vdom_param

DNS_DB = "/api/v2/cmdb/system/dns-database"
ADDRESS = "/api/v2/cmdb/firewall/address"
ADDRGRP = "/api/v2/cmdb/firewall/addrgrp"

TOOLS = [
    {
        "name": "k8s_cluster_overview",
        "description": (
            "Read the Kubernetes cluster from K8S_KUBECONFIG: nodes with IPs and readiness, "
            "LoadBalancer services with their IPs (e.g. Traefik on k3s ServiceLB) and every Ingress "
            "or Traefik IngressRoute hostname. Read-only."
        ),
        "inputSchema": schema({}),
    },
    {
        "name": "k8s_sync_ingress_dns",
        "description": (
            "Create FortiGate DNS records for the cluster's Ingress hostnames that fall inside a "
            "local zone (e.g. whoami.lab in zone 'lab'), pointing at the IPs the ingress is served "
            "on. This replaces the wildcard record FortiOS cannot do. Hosts outside the zone, "
            "wildcard hosts and the zone apex are skipped and listed. prune=true also removes "
            "records that point at the ingress IPs but no longer match any Ingress. "
            "dry_run defaults to true."
        ),
        "inputSchema": schema(
            {
                "zone": STR("FortiGate DNS zone object name, e.g. lab"),
                "fallback_service": STR(
                    "namespace/name of the LoadBalancer service whose IPs to use when an Ingress has "
                    "no status IPs (default kube-system/traefik)"
                ),
                "prune": BOOL("Remove stale records that point at ingress IPs (default false)"),
                "dry_run": BOOL("Only return the plan (default true)"),
            },
            ["zone"],
        ),
    },
    {
        "name": "k8s_sync_node_addresses",
        "description": (
            "Keep a FortiGate address object in step with the cluster's node IPs so policies follow "
            "the cluster. If the target is an address (range or subnet), it is set to the range "
            "first..last node IP; non-contiguous IPs are refused unless allow_gaps=true, since a "
            "range would then cover non-node hosts. If the target is an address group, one /32 "
            "address per node (<target>-<node>) is kept as its members. Missing targets are created "
            "as a range when possible, otherwise as a group. dry_run defaults to true."
        ),
        "inputSchema": schema(
            {
                "target": STR("Address or address group name (default K3S-NODES)"),
                "allow_gaps": BOOL("Allow a range that also covers non-node IPs (default false)"),
                "dry_run": BOOL("Only return the plan (default true)"),
            }
        ),
    },
]

_kube: KubeClient | None = None


def kube() -> KubeClient:
    global _kube
    if _kube is None:
        _kube = KubeClient()
    return _kube


async def aclose() -> None:
    if _kube is not None:
        await _kube.close()


async def _get_or_none(client: FortiGateClient, path: str, v: dict[str, Any]) -> Any:
    try:
        return one(await client.get(path, v))
    except FortiGateAPIError as e:
        if e.status == 404:
            return None
        raise


async def _sync_dns(args: dict[str, Any], client: FortiGateClient, v: dict[str, Any]) -> dict[str, Any]:
    k = kube()
    zone_name = args["zone"]
    zone = await _get_or_none(client, f"{DNS_DB}/{mkey(zone_name)}", v)
    if not isinstance(zone, dict):
        raise ValueError(f"DNS zone {zone_name!r} not found on the FortiGate")
    domain = zone.get("domain", "").rstrip(".").lower()

    fallback = args.get("fallback_service", "kube-system/traefik")
    lbs = await k.load_balancers()
    fb_ips = next((lb["ips"] for lb in lbs if f"{lb['namespace']}/{lb['name']}" == fallback), [])
    lb_ips = {ip for lb in lbs for ip in lb["ips"]}

    desired: dict[str, set[str]] = {}
    skipped = []
    for item in await k.ingress_hosts():
        host = item["host"].rstrip(".").lower()
        if "*" in host:
            skipped.append({"host": host, "reason": "wildcard hosts are not supported by FortiOS DNS"})
        elif host == domain:
            skipped.append({"host": host, "reason": "zone apex"})
        elif not host.endswith("." + domain):
            skipped.append({"host": host, "reason": f"outside zone {domain!r}"})
        else:
            ips = item["ips"] or fb_ips
            if not ips:
                skipped.append({"host": host, "reason": f"no ingress IPs and no IPs on {fallback}"})
                continue
            desired.setdefault(host[: -len(domain) - 1], set()).update(ips)

    existing: dict[tuple[str, str], int] = {}
    for e in zone.get("dns-entry") or []:
        if e.get("type") == "A":
            existing[(e.get("hostname", "").lower(), e.get("ip"))] = e.get("id")

    add = sorted((h, ip) for h, ips in desired.items() for ip in ips if (h, ip) not in existing)
    remove = []
    if args.get("prune"):
        managed_ips = lb_ips | {ip for ips in desired.values() for ip in ips}
        for (h, ip), eid in existing.items():
            if ip in managed_ips and ip not in desired.get(h, set()):
                remove.append({"id": eid, "hostname": h, "ip": ip})

    plan = {
        "zone": zone_name,
        "domain": domain,
        "add": [{"hostname": h, "fqdn": f"{h}.{domain}", "ip": ip} for h, ip in add],
        "remove": remove,
        "unchanged": sorted(f"{h}.{domain} -> {ip}" for h, ips in desired.items() for ip in ips if (h, ip) in existing),
        "skipped": skipped,
    }
    if args.get("dry_run", True):
        return {"dry_run": True, **plan}

    base = f"{DNS_DB}/{mkey(zone_name)}/dns-entry"
    next_id = max(existing.values(), default=0) + 1
    for h, ip in add:
        await client.post(base, {"id": next_id, "status": "enable", "type": "A", "hostname": h, "ip": ip}, v)
        next_id += 1
    for r in remove:
        await client.delete(f"{base}/{r['id']}", v)
    return {"dry_run": False, **plan}


def _contiguous(ips: list[ipaddress.IPv4Address]) -> bool:
    return int(ips[-1]) - int(ips[0]) + 1 == len(ips)


async def _sync_nodes(args: dict[str, Any], client: FortiGateClient, v: dict[str, Any]) -> dict[str, Any]:
    target = args.get("target", "K3S-NODES")
    nodes = [n for n in await kube().nodes() if n.get("internal_ip")]
    if not nodes:
        raise ValueError("The cluster reports no nodes with an InternalIP")
    ips = sorted(ipaddress.IPv4Address(n["internal_ip"]) for n in nodes)
    dry = args.get("dry_run", True)
    plan: dict[str, Any] = {"target": target, "nodes": {n["name"]: n["internal_ip"] for n in nodes}}

    addr = await _get_or_none(client, f"{ADDRESS}/{mkey(target)}", v)
    group = None if addr else await _get_or_none(client, f"{ADDRGRP}/{mkey(target)}", v)

    if addr or (not group and _contiguous(ips)) or (not group and args.get("allow_gaps")):
        if not _contiguous(ips) and not args.get("allow_gaps"):
            raise ValueError(
                f"Node IPs {[str(i) for i in ips]} are not contiguous, so a range on {target!r} would "
                "cover other hosts. Use an address group as the target, or allow_gaps=true."
            )
        want = {"type": "iprange", "start-ip": str(ips[0]), "end-ip": str(ips[-1])}
        current = {k: (addr or {}).get(k) for k in want}
        plan["kind"] = "address range"
        plan["current"] = current if addr else None
        plan["desired"] = want
        plan["action"] = "none" if current == want else ("update" if addr else "create")
        if not dry and plan["action"] == "update":
            await client.put(f"{ADDRESS}/{mkey(target)}", want, v)
        elif not dry and plan["action"] == "create":
            await client.post(ADDRESS, {"name": target, **want, "comment": "k8s nodes (synced)"}, v)
        return {"dry_run": dry, **plan}

    # Address group: one /32 per node, named <target>-<node>.
    prefix = f"{target}-"
    member_names = [f"{prefix}{n['name']}"[:79] for n in nodes]
    plan["kind"] = "address group"
    plan["current_members"] = [m["name"] for m in (group or {}).get("member") or []]
    plan["desired_members"] = member_names
    upserts = []
    for n, mname in zip(nodes, member_names, strict=True):
        cur = await _get_or_none(client, f"{ADDRESS}/{mkey(mname)}", v)
        want_subnet = f"{n['internal_ip']} 255.255.255.255"
        if not cur:
            upserts.append(("create", mname, want_subnet))
        elif cur.get("subnet") != want_subnet:
            upserts.append(("update", mname, want_subnet))
    stale = [m for m in plan["current_members"] if m.startswith(prefix) and m not in member_names]
    plan["address_changes"] = [{"action": a, "name": n, "subnet": s} for a, n, s in upserts]
    plan["remove_members"] = stale
    if dry:
        return {"dry_run": True, **plan}

    for action, mname, subnet_ in upserts:
        if action == "create":
            await client.post(ADDRESS, {"name": mname, "subnet": subnet_, "comment": "k8s node (synced)"}, v)
        else:
            await client.put(f"{ADDRESS}/{mkey(mname)}", {"subnet": subnet_}, v)
    if group:
        await client.put(f"{ADDRGRP}/{mkey(target)}", {"member": names(member_names)}, v)
    else:
        await client.post(ADDRGRP, {"name": target, "member": names(member_names), "comment": "k8s nodes (synced)"}, v)
    for m in stale:
        await client.delete(f"{ADDRESS}/{mkey(m)}", v)
    return {"dry_run": False, **plan}


async def handle(name: str, args: dict[str, Any], client: FortiGateClient) -> Any:
    v = vdom_param(args)

    if name == "k8s_cluster_overview":
        k = kube()
        return {
            "server": k.server,
            "context": k.context,
            "nodes": await k.nodes(),
            "load_balancers": await k.load_balancers(),
            "ingress_hosts": await k.ingress_hosts(),
        }

    elif name == "k8s_sync_ingress_dns":
        return await _sync_dns(args, client, v)

    elif name == "k8s_sync_node_addresses":
        return await _sync_nodes(args, client, v)

    raise ValueError(f"Unknown tool: {name}")

