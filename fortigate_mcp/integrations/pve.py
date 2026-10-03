"""Read-only Proxmox VE lookup: which VM or container owns a MAC address.

Uses the same environment variables as proxmox-mcp-server (PROXMOX_HOST, PROXMOX_PORT,
PROXMOX_USER, PROXMOX_TOKEN_NAME, PROXMOX_TOKEN_VALUE, PROXMOX_VERIFY_SSL). Only GET requests are
made, so an API token with the PVEAuditor role is enough.
"""

from __future__ import annotations

import os
import re
import time
from typing import Any

import httpx

from ..tools._common import results

PROXMOX_HOST = os.getenv("PROXMOX_HOST", "")
PROXMOX_PORT = os.getenv("PROXMOX_PORT", "8006")
PROXMOX_USER = os.getenv("PROXMOX_USER", "")
PROXMOX_TOKEN_NAME = os.getenv("PROXMOX_TOKEN_NAME", "")
PROXMOX_TOKEN_VALUE = os.getenv("PROXMOX_TOKEN_VALUE", "")
PROXMOX_VERIFY_SSL = os.getenv("PROXMOX_VERIFY_SSL", "false").lower() == "true"
CACHE_SECONDS = 60

_MAC = re.compile(r"(?:^|,)(?:[a-z0-9]+=)?((?:[0-9a-f]{2}:){5}[0-9a-f]{2})", re.I)


def enabled() -> bool:
    return bool(PROXMOX_HOST and PROXMOX_USER and PROXMOX_TOKEN_NAME and PROXMOX_TOKEN_VALUE)


def _nic(value: str) -> dict[str, Any]:
    """Parse a qemu netN (virtio=MAC,bridge=..,tag=..) or lxc netN (hwaddr=MAC,...) value."""
    parts = dict(p.split("=", 1) for p in value.split(",") if "=" in p)
    m = _MAC.search(value)
    return {"mac": m.group(1).lower() if m else None, "bridge": parts.get("bridge"), "tag": parts.get("tag")}


class ProxmoxLookup:
    def __init__(self) -> None:
        self.client = httpx.AsyncClient(
            base_url=f"https://{PROXMOX_HOST}:{PROXMOX_PORT}/api2/json",
            verify=PROXMOX_VERIFY_SSL,
            timeout=20.0,
            headers={"Authorization": f"PVEAPIToken={PROXMOX_USER}!{PROXMOX_TOKEN_NAME}={PROXMOX_TOKEN_VALUE}"},
        )
        self._by_mac: dict[str, dict[str, Any]] = {}
        self._loaded = 0.0

    async def _get(self, path: str) -> Any:
        r = await self.client.get(path)
        if r.status_code >= 400:
            raise RuntimeError(f"Proxmox GET {path} -> HTTP {r.status_code}: {r.text[:200]}")
        return r.json().get("data")

    async def by_mac(self) -> dict[str, dict[str, Any]]:
        if self._by_mac and time.monotonic() - self._loaded < CACHE_SECONDS:
            return self._by_mac
        found: dict[str, dict[str, Any]] = {}
        for res in await self._get("/cluster/resources?type=vm") or []:
            kind, node, vmid = res.get("type"), res.get("node"), res.get("vmid")
            if kind not in ("qemu", "lxc"):
                continue
            cfg = await self._get(f"/nodes/{node}/{kind}/{vmid}/config") or {}
            for key, val in cfg.items():
                if re.fullmatch(r"net\d+", key) and isinstance(val, str):
                    nic = _nic(val)
                    if nic["mac"]:
                        found[nic["mac"]] = {
                            "vmid": vmid, "name": res.get("name"), "type": kind, "node": node,
                            "status": res.get("status"), "nic": key, "bridge": nic["bridge"], "vlan": nic["tag"],
                        }
        self._by_mac, self._loaded = found, time.monotonic()
        return found

    async def close(self) -> None:
        await self.client.aclose()


_lookup: ProxmoxLookup | None = None


def lookup() -> ProxmoxLookup:
    global _lookup
    if not enabled():
        raise ValueError(
            "Proxmox lookups need PROXMOX_HOST, PROXMOX_USER, PROXMOX_TOKEN_NAME and PROXMOX_TOKEN_VALUE "
            "(a read-only PVEAuditor token is enough)"
        )
    if _lookup is None:
        _lookup = ProxmoxLookup()
    return _lookup


async def aclose() -> None:
    if _lookup is not None:
        await _lookup.close()


def label(vm: dict[str, Any] | None) -> str | None:
    return f"{vm['vmid']} {vm['name']} ({vm['type']} on {vm['node']})" if vm else None


IP_FIELDS = ("srcip", "dstip", "ip", "srcaddr", "dstaddr")
MAC_FIELDS = ("mac", "srcmac", "dstmac")


async def ip_to_mac(fgt: Any, v: dict[str, Any]) -> dict[str, str]:
    """IP -> MAC from the FortiGate's ARP table and DHCP leases."""
    out: dict[str, str] = {}
    leases = results(await fgt.get("/api/v2/monitor/system/dhcp", v))
    for lease in leases if isinstance(leases, list) else []:
        if lease.get("ip") and lease.get("mac"):
            out[lease["ip"]] = lease["mac"].lower()
    arp = results(await fgt.get("/api/v2/monitor/network/arp", v))
    for a in arp if isinstance(arp, list) else []:
        if a.get("ip") and a.get("mac"):
            out[a["ip"]] = a["mac"].lower()
    return out


async def annotate(rows: list[dict[str, Any]], fgt: Any, v: dict[str, Any]) -> list[dict[str, Any]]:
    """Add <field>_vm labels to rows whose IP or MAC fields belong to a Proxmox VM."""
    vms = await lookup().by_mac()
    macs = await ip_to_mac(fgt, v)
    for row in rows:
        for f in IP_FIELDS:
            ip = row.get(f)
            if isinstance(ip, str) and (vm := vms.get(macs.get(ip, ""))):
                row[f"{f}_vm"] = label(vm)
        for f in MAC_FIELDS:
            mac = row.get(f)
            if isinstance(mac, str) and (vm := vms.get(mac.lower())) and f"{f}_vm" not in row:
                row[f"{f}_vm"] = label(vm)
    return rows
