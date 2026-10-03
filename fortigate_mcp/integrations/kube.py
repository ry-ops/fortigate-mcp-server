"""Minimal, read-only Kubernetes API client built from a kubeconfig.

Only GET requests are made: the integration reads nodes, services and ingresses and writes
nothing to the cluster. Supports certificate, token and basic kubeconfig users (not exec plugins).
"""

from __future__ import annotations

import base64
import os
import re
import ssl
import tempfile
from typing import Any

import httpx
import yaml

K8S_KUBECONFIG = os.getenv("K8S_KUBECONFIG", "")
K8S_CONTEXT = os.getenv("K8S_CONTEXT", "")


def enabled() -> bool:
    return bool(K8S_KUBECONFIG)


def _named(items: list[dict[str, Any]], name: str, kind: str) -> dict[str, Any]:
    for item in items or []:
        if item.get("name") == name:
            return item.get(kind) or {}
    raise ValueError(f"kubeconfig has no {kind} named {name!r}")


def _pem(data_b64: str | None, path: str | None) -> bytes | None:
    if data_b64:
        return base64.b64decode(data_b64)
    if path:
        with open(os.path.expanduser(path), "rb") as f:
            return f.read()
    return None


class KubeClient:
    def __init__(self, kubeconfig: str | None = None, context: str | None = None) -> None:
        with open(os.path.expanduser(kubeconfig or K8S_KUBECONFIG)) as f:
            cfg = yaml.safe_load(f)
        ctx_name = context or K8S_CONTEXT or cfg.get("current-context")
        ctx = _named(cfg.get("contexts", []), ctx_name, "context")
        cluster = _named(cfg.get("clusters", []), ctx["cluster"], "cluster")
        user = _named(cfg.get("users", []), ctx["user"], "user")
        if "exec" in user or "auth-provider" in user:
            raise ValueError("kubeconfig exec/auth-provider users are not supported; use a cert or token user")

        self.server = cluster["server"].rstrip("/")
        self.context = ctx_name
        headers: dict[str, str] = {}

        if cluster.get("insecure-skip-tls-verify"):
            sslctx: ssl.SSLContext | bool = False
        else:
            ca = _pem(cluster.get("certificate-authority-data"), cluster.get("certificate-authority"))
            sslctx = ssl.create_default_context(cadata=ca.decode()) if ca else ssl.create_default_context()

        cert = _pem(user.get("client-certificate-data"), user.get("client-certificate"))
        key = _pem(user.get("client-key-data"), user.get("client-key"))
        if cert and key:
            if sslctx is False:
                sslctx = ssl.create_default_context()
                sslctx.check_hostname = False
                sslctx.verify_mode = ssl.CERT_NONE
            # load_cert_chain only reads files: write them privately, load, delete at once.
            with tempfile.TemporaryDirectory() as tmp:
                cpath, kpath = os.path.join(tmp, "c.pem"), os.path.join(tmp, "k.pem")
                for path, data in ((cpath, cert), (kpath, key)):
                    fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
                    with os.fdopen(fd, "wb") as f:
                        f.write(data)
                assert isinstance(sslctx, ssl.SSLContext)
                sslctx.load_cert_chain(cpath, kpath)
        elif user.get("token"):
            headers["Authorization"] = f"Bearer {user['token']}"
        elif user.get("username") and user.get("password"):
            raw = f"{user['username']}:{user['password']}".encode()
            headers["Authorization"] = "Basic " + base64.b64encode(raw).decode()

        self.client = httpx.AsyncClient(base_url=self.server, verify=sslctx, headers=headers, timeout=20.0)

    async def get(self, path: str, missing_ok: bool = False) -> Any:
        r = await self.client.get(path)
        if missing_ok and r.status_code == 404:
            return None
        if r.status_code >= 400:
            raise RuntimeError(f"Kubernetes GET {path} -> HTTP {r.status_code}: {r.text[:200]}")
        return r.json()

    async def close(self) -> None:
        await self.client.aclose()

    # --- the views the tools need ---

    async def nodes(self) -> list[dict[str, Any]]:
        out = []
        for n in (await self.get("/api/v1/nodes")).get("items", []):
            addrs = {a["type"]: a["address"] for a in n.get("status", {}).get("addresses", [])}
            ready = next((c["status"] for c in n.get("status", {}).get("conditions", []) if c["type"] == "Ready"), "Unknown")
            roles = sorted(k.split("/", 1)[1] for k in n["metadata"].get("labels", {}) if k.startswith("node-role.kubernetes.io/"))
            out.append({"name": n["metadata"]["name"], "internal_ip": addrs.get("InternalIP"),
                        "ready": ready == "True", "roles": roles or ["worker"]})
        return out

    async def load_balancers(self) -> list[dict[str, Any]]:
        out = []
        for s in (await self.get("/api/v1/services")).get("items", []):
            if s.get("spec", {}).get("type") != "LoadBalancer":
                continue
            ips = [i.get("ip") for i in s.get("status", {}).get("loadBalancer", {}).get("ingress", []) if i.get("ip")]
            out.append({"namespace": s["metadata"]["namespace"], "name": s["metadata"]["name"], "ips": ips,
                        "ports": [f"{p.get('port')}/{p.get('protocol', 'TCP')}" for p in s["spec"].get("ports", [])]})
        return out

    async def ingress_hosts(self) -> list[dict[str, Any]]:
        """Hostnames from Ingress objects and Traefik IngressRoutes, with the IPs they are served on."""
        out = []
        for ing in (await self.get("/apis/networking.k8s.io/v1/ingresses")).get("items", []):
            ips = [i.get("ip") for i in ing.get("status", {}).get("loadBalancer", {}).get("ingress", []) if i.get("ip")]
            hosts = {r.get("host") for r in ing.get("spec", {}).get("rules", []) if r.get("host")}
            for tls in ing.get("spec", {}).get("tls", []) or []:
                hosts.update(h for h in tls.get("hosts", []) if h)
            for h in sorted(hosts):
                out.append({"host": h, "ips": ips, "source": f"Ingress {ing['metadata']['namespace']}/{ing['metadata']['name']}"})
        routes = await self.get("/apis/traefik.io/v1alpha1/ingressroutes", missing_ok=True)
        for ir in (routes or {}).get("items", []):
            for route in ir.get("spec", {}).get("routes", []):
                for h in re.findall(r"Host\(([^)]*)\)", route.get("match", "")):
                    for host in re.findall(r"[`\"']([^`\"']+)[`\"']", h):
                        out.append({"host": host, "ips": [],
                                    "source": f"IngressRoute {ir['metadata']['namespace']}/{ir['metadata']['name']}"})
        return out
