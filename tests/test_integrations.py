"""Kubernetes and Proxmox integrations."""

import httpx
import pytest
import yaml

from fortigate_mcp.integrations import kube, pve
from fortigate_mcp.tools import k8s
from fortigate_mcp.tools import pve as pve_tools

ZONE = "/api/v2/cmdb/system/dns-database/lab"
TRAEFIK_IPS = ["192.168.150.10", "192.168.150.11"]


class FakeKube:
    def __init__(self, hosts=(), nodes=(), lbs=None):
        self._hosts, self._nodes = list(hosts), list(nodes)
        self._lbs = lbs if lbs is not None else [{"namespace": "kube-system", "name": "traefik", "ips": TRAEFIK_IPS, "ports": []}]
        self.server, self.context = "https://k8s.test:6443", "test"

    async def ingress_hosts(self):
        return self._hosts

    async def nodes(self):
        return self._nodes

    async def load_balancers(self):
        return self._lbs


def test_kubeconfig_token_user(tmp_path):
    cfg = {"current-context": "c", "contexts": [{"name": "c", "context": {"cluster": "k", "user": "u"}}],
           "clusters": [{"name": "k", "cluster": {"server": "https://10.0.0.1:6443/", "insecure-skip-tls-verify": True}}],
           "users": [{"name": "u", "user": {"token": "abc"}}]}
    path = tmp_path / "kc.yaml"
    path.write_text(yaml.safe_dump(cfg))
    k = kube.KubeClient(str(path))
    assert k.server == "https://10.0.0.1:6443" and k.client.headers["Authorization"] == "Bearer abc"


def test_kubeconfig_exec_user_refused(tmp_path):
    cfg = {"current-context": "c", "contexts": [{"name": "c", "context": {"cluster": "k", "user": "u"}}],
           "clusters": [{"name": "k", "cluster": {"server": "https://x"}}],
           "users": [{"name": "u", "user": {"exec": {"command": "aws"}}}]}
    path = tmp_path / "kc.yaml"
    path.write_text(yaml.safe_dump(cfg))
    with pytest.raises(ValueError, match="exec"):
        kube.KubeClient(str(path))


async def test_kube_ingress_hosts_include_tls_and_ingressroutes():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/ingresses"):
            return httpx.Response(200, json={"items": [{"metadata": {"namespace": "demo", "name": "w"},
                "spec": {"rules": [{"host": "whoami.lab"}], "tls": [{"hosts": ["secure.lab"]}]},
                "status": {"loadBalancer": {"ingress": [{"ip": "192.168.150.10"}]}}}]})
        return httpx.Response(200, json={"items": [{"metadata": {"namespace": "demo", "name": "r"},
            "spec": {"routes": [{"match": "Host(`a.lab`) || Host(`b.lab`)"}]}}]})

    k = kube.KubeClient.__new__(kube.KubeClient)
    k.client = httpx.AsyncClient(base_url="https://k8s.test", transport=httpx.MockTransport(handler))
    hosts = {h["host"]: h for h in await k.ingress_hosts()}
    assert set(hosts) == {"whoami.lab", "secure.lab", "a.lab", "b.lab"}
    assert hosts["whoami.lab"]["ips"] == ["192.168.150.10"] and hosts["a.lab"]["source"] == "IngressRoute demo/r"


async def test_dns_sync_plan_skips_and_fallback(monkeypatch, fgt):
    c, rec = fgt
    monkeypatch.setattr(k8s, "_kube", FakeKube(hosts=[
        {"host": "whoami.lab", "ips": [], "source": "Ingress demo/whoami"},      # uses Traefik fallback IPs
        {"host": "*.lab", "ips": TRAEFIK_IPS, "source": "x"},
        {"host": "lab", "ips": TRAEFIK_IPS, "source": "x"},
        {"host": "app.example.com", "ips": TRAEFIK_IPS, "source": "x"},
    ]))
    rec.respond("GET", ZONE, 200, {"results": [{"name": "lab", "domain": "lab", "dns-entry": [
        {"id": 7, "type": "A", "hostname": "whoami", "ip": "192.168.150.10"}]}]})
    plan = await k8s.handle("k8s_sync_ingress_dns", {"zone": "lab"}, c)
    assert plan["dry_run"] is True
    assert plan["add"] == [{"hostname": "whoami", "fqdn": "whoami.lab", "ip": "192.168.150.11"}]
    assert plan["unchanged"] == ["whoami.lab -> 192.168.150.10"]
    assert {s["host"] for s in plan["skipped"]} == {"*.lab", "lab", "app.example.com"}
    assert not any(r.method in ("POST", "DELETE") for r in rec.requests)


async def test_dns_sync_apply_and_prune(monkeypatch, fgt):
    c, rec = fgt
    monkeypatch.setattr(k8s, "_kube", FakeKube(hosts=[{"host": "new.lab", "ips": ["192.168.150.10"], "source": "x"}]))
    rec.respond("GET", ZONE, 200, {"results": [{"name": "lab", "domain": "lab", "dns-entry": [
        {"id": 3, "type": "A", "hostname": "old", "ip": "192.168.150.11"},       # points at Traefik: stale
        {"id": 4, "type": "A", "hostname": "k3s-master", "ip": "192.168.150.99"},  # not an ingress IP: kept
    ]}]})
    out = await k8s.handle("k8s_sync_ingress_dns", {"zone": "lab", "prune": True, "dry_run": False}, c)
    posts = [r for r in rec.requests if r.method == "POST"]
    deletes = [r for r in rec.requests if r.method == "DELETE"]
    assert len(posts) == 1 and rec.body(rec.requests.index(posts[0]))["hostname"] == "new"
    assert rec.body(rec.requests.index(posts[0]))["id"] == 5
    assert [d.url.path for d in deletes] == [f"{ZONE}/dns-entry/3"]
    assert out["remove"] == [{"id": 3, "hostname": "old", "ip": "192.168.150.11"}]


NODES = [{"name": "m", "internal_ip": "192.168.150.10"}, {"name": "w1", "internal_ip": "192.168.150.11"}]


async def test_node_sync_updates_range(monkeypatch, fgt):
    c, rec = fgt
    monkeypatch.setattr(k8s, "_kube", FakeKube(nodes=NODES))
    rec.respond("GET", "/api/v2/cmdb/firewall/address/K3S-NODES", 200, {"results": [
        {"name": "K3S-NODES", "type": "iprange", "start-ip": "192.168.150.10", "end-ip": "192.168.150.12"}]})
    out = await k8s.handle("k8s_sync_node_addresses", {"dry_run": False}, c)
    assert out["action"] == "update"
    assert rec.body() == {"type": "iprange", "start-ip": "192.168.150.10", "end-ip": "192.168.150.11"}


async def test_node_sync_refuses_gaps(monkeypatch, fgt):
    c, rec = fgt
    monkeypatch.setattr(k8s, "_kube", FakeKube(nodes=[*NODES, {"name": "w9", "internal_ip": "192.168.150.20"}]))
    rec.respond("GET", "/api/v2/cmdb/firewall/address/K3S-NODES", 200, {"results": [{"name": "K3S-NODES", "type": "iprange"}]})
    with pytest.raises(ValueError, match="not contiguous"):
        await k8s.handle("k8s_sync_node_addresses", {}, c)


async def test_node_sync_group_mode(monkeypatch, fgt):
    c, rec = fgt
    monkeypatch.setattr(k8s, "_kube", FakeKube(nodes=NODES))
    rec.respond("GET", "/api/v2/cmdb/firewall/address/NODES", 404, {"http_status": 404})
    rec.respond("GET", "/api/v2/cmdb/firewall/addrgrp/NODES", 200, {"results": [
        {"name": "NODES", "member": [{"name": "NODES-m"}, {"name": "NODES-gone"}]}]})
    rec.respond("GET", "/api/v2/cmdb/firewall/address/NODES-m", 200, {"results": [{"name": "NODES-m", "subnet": "192.168.150.10 255.255.255.255"}]})
    rec.respond("GET", "/api/v2/cmdb/firewall/address/NODES-w1", 404, {"http_status": 404})
    out = await k8s.handle("k8s_sync_node_addresses", {"target": "NODES", "dry_run": False}, c)
    assert out["address_changes"] == [{"action": "create", "name": "NODES-w1", "subnet": "192.168.150.11 255.255.255.255"}]
    assert out["remove_members"] == ["NODES-gone"]
    group_put = next(r for r in rec.requests if r.method == "PUT")
    assert rec.body(rec.requests.index(group_put)) == {"member": [{"name": "NODES-m"}, {"name": "NODES-w1"}]}
    assert rec.requests[-1].method == "DELETE" and rec.requests[-1].url.path.endswith("/NODES-gone")


@pytest.mark.parametrize("value, mac, tag", [
    ("virtio=BC:24:11:00:00:01,bridge=vmbr1,tag=150", "bc:24:11:00:00:01", "150"),
    ("name=eth0,bridge=vmbr1,hwaddr=BC:24:11:AA:BB:CC,ip=dhcp,type=veth", "bc:24:11:aa:bb:cc", None),
])
def test_pve_nic_parsing(value, mac, tag):
    nic = pve._nic(value)
    assert nic["mac"] == mac and nic["bridge"] == "vmbr1" and nic["tag"] == tag


class FakeLookup:
    async def by_mac(self):
        return {"bc:24:11:00:00:01": {"vmid": 110, "name": "k3s-master", "type": "qemu", "node": "pve01", "vlan": "150"}}


async def test_annotate_and_identify(monkeypatch, fgt):
    c, rec = fgt
    monkeypatch.setattr(pve, "lookup", lambda: FakeLookup())
    rec.respond("GET", "/api/v2/monitor/system/dhcp", 200, {"results": [
        {"ip": "192.168.150.10", "mac": "BC:24:11:00:00:01", "interface": "port2", "hostname": "k3s-master"}]})
    rec.respond("GET", "/api/v2/monitor/network/arp", 200, {"results": [
        {"ip": "10.0.0.1", "mac": "02:00:00:00:00:01", "interface": "port1"}]})
    rows = await pve.annotate([{"srcip": "192.168.150.10", "dstip": "1.1.1.1"}], c, {})
    assert rows == [{"srcip": "192.168.150.10", "dstip": "1.1.1.1", "srcip_vm": "110 k3s-master (qemu on pve01)"}]
    out = await pve_tools.handle("identify_clients", {}, c)
    assert [(x["ip"], x["label"]) for x in out] == [("10.0.0.1", None), ("192.168.150.10", "110 k3s-master (qemu on pve01)")]
