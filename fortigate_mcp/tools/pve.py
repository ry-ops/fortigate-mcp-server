"""Proxmox integration: name the VMs behind the FortiGate's clients.

Enabled when the PROXMOX_* variables are set (same names as proxmox-mcp-server). Other tools
(get_logs, list_sessions, get_top_traffic, list_dhcp_leases) accept resolve_vms=true to label
IPs and MACs with the Proxmox VM they belong to.
"""

from __future__ import annotations

from typing import Any

from ..client import FortiGateClient
from ..integrations import pve
from ._common import STR, results, schema, vdom_param

TOOLS = [
    {
        "name": "identify_clients",
        "description": (
            "Every client the FortiGate knows (DHCP leases and ARP entries) matched by MAC address to "
            "the Proxmox VM or container that owns it: VMID, name, node, status, bridge and VLAN tag. "
            "Clients with no Proxmox match (physical devices, the upstream gateway) are listed too."
        ),
        "inputSchema": schema({"interface": STR("Only clients on this FortiGate interface, e.g. port2")}),
    },
]


async def handle(name: str, args: dict[str, Any], client: FortiGateClient) -> Any:
    v = vdom_param(args)

    if name == "identify_clients":
        vms = await pve.lookup().by_mac()
        clients: dict[str, dict[str, Any]] = {}
        leases = results(await client.get("/api/v2/monitor/system/dhcp", v))
        for lease in leases if isinstance(leases, list) else []:
            mac = (lease.get("mac") or "").lower()
            clients[mac] = {"ip": lease.get("ip"), "mac": mac, "interface": lease.get("interface"),
                            "dhcp_hostname": lease.get("hostname"), "reserved": lease.get("reserved"),
                            "source": "dhcp"}
        arp = results(await client.get("/api/v2/monitor/network/arp", v))
        for a in arp if isinstance(arp, list) else []:
            mac = (a.get("mac") or "").lower()
            if mac and mac not in clients:
                clients[mac] = {"ip": a.get("ip"), "mac": mac, "interface": a.get("interface"), "source": "arp"}
        out = []
        for c in clients.values():
            if args.get("interface") and c.get("interface") != args["interface"]:
                continue
            vm = vms.get(c["mac"])
            out.append({**c, "proxmox": vm, "label": pve.label(vm)})
        return sorted(out, key=lambda c: (c.get("interface") or "", c.get("ip") or ""))

    raise ValueError(f"Unknown tool: {name}")
