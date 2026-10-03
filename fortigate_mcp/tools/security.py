"""SSL/SSH inspection profiles and certificates."""

from __future__ import annotations

import base64
import hashlib
from typing import Any

from ..client import FortiGateClient
from ._common import (
    EXTRA,
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

SSL_PROFILE = "/api/v2/cmdb/firewall/ssl-ssh-profile"
READ_ONLY_PROFILES = {"no-inspection", "certificate-inspection", "deep-inspection"}
WEAK_KEY_BITS = 2048

TOOLS = [
    {
        "name": "list_ssl_ssh_profiles",
        "description": (
            "List SSL/SSH inspection profiles with the CA each one re-signs with. The built-in "
            "no-inspection, certificate-inspection and deep-inspection profiles are read-only; "
            "edit custom-deep-inspection or a copy instead."
        ),
        "inputSchema": schema({**LIST_PROPS}),
    },
    {
        "name": "update_ssl_ssh_profile",
        "description": (
            "Update an SSL/SSH inspection profile, e.g. the CA used to re-sign certificates during "
            "deep inspection. Clients must trust that CA, and FortiGate-VM evaluation licenses "
            "re-sign RSA sites with 512-bit keys regardless of the CA, which modern clients reject."
        ),
        "inputSchema": schema(
            {
                "name": STR("Profile name, e.g. custom-deep-inspection"),
                "caname": STR("CA certificate used to re-sign trusted sites"),
                "untrusted_caname": STR("CA used to re-sign sites with untrusted certificates"),
                "comment": STR("Comment"),
                "extra": EXTRA,
            },
            ["name"],
        ),
    },
    {
        "name": "list_certificates",
        "description": (
            "List local and CA certificates with key type and size, validity and usage flags. "
            f"Certificates with RSA keys under {WEAK_KEY_BITS} bits are flagged weak: FortiGate-VM "
            "evaluation licenses generate 512-bit factory certificates. Bundled public CAs are "
            "omitted unless include_bundle is true."
        ),
        "inputSchema": schema(
            {
                "include_bundle": {"type": "boolean", "description": "Include the ~150 bundled public CAs"},
                "name_contains": STR("Only certificates whose name contains this text"),
            }
        ),
    },
    {
        "name": "download_certificate",
        "description": (
            "Download a certificate's PEM (public part only), e.g. the deep-inspection CA "
            "Fortinet_CA_SSL so clients can be told to trust it. Returns the PEM and its SHA-256 fingerprint."
        ),
        "inputSchema": schema(
            {
                "name": STR("Certificate name, e.g. Fortinet_CA_SSL"),
                "type": STR("local-ca (default), local-cer, remote-cer, ca or crl"),
            },
            ["name"],
        ),
    },
]


def _fingerprint(pem: str) -> str:
    der = base64.b64decode("".join(ln for ln in pem.splitlines() if ln and not ln.startswith("-----")))
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


async def handle(name: str, args: dict[str, Any], client: FortiGateClient) -> Any:
    v = vdom_param(args)

    if name == "list_ssl_ssh_profiles":
        profiles = results(await client.get(SSL_PROFILE, list_params(args)))
        if isinstance(profiles, list) and not args.get("format"):
            return [
                {
                    "name": p.get("name"),
                    "comment": p.get("comment"),
                    "caname": p.get("caname"),
                    "untrusted-caname": p.get("untrusted-caname"),
                    "https": (p.get("https") or {}).get("status"),
                    "ssl-exempt": len(p.get("ssl-exempt") or []),
                    "read_only": p.get("name") in READ_ONLY_PROFILES,
                }
                for p in profiles
            ]
        return profiles

    elif name == "update_ssl_ssh_profile":
        if args["name"] in READ_ONLY_PROFILES:
            raise ValueError(f"{args['name']!r} is a read-only built-in profile; edit custom-deep-inspection or a copy")
        data = body(args, {"caname": "caname", "untrusted_caname": "untrusted-caname", "comment": "comment"})
        return write_result(await client.put(f"{SSL_PROFILE}/{mkey(args['name'])}", data, v))

    elif name == "list_certificates":
        certs = results(await client.get("/api/v2/monitor/system/available-certificates", {**v, "scope": "global"}))
        if not isinstance(certs, list):
            return certs
        out = []
        for c in certs:
            if not args.get("include_bundle") and c.get("source") == "bundle":
                continue
            if args.get("name_contains") and args["name_contains"].lower() not in str(c.get("name", "")).lower():
                continue
            row = {
                k: c.get(k)
                for k in ("name", "type", "source", "key_type", "key_size", "status", "is_ca",
                          "is_deep_inspection_cert", "subject", "issuer", "valid_to", "fingerprint")
            }
            if c.get("key_type") == "RSA" and isinstance(c.get("key_size"), int) and c["key_size"] < WEAK_KEY_BITS:
                row["weak"] = True
            out.append(row)
        return out

    elif name == "download_certificate":
        params = {**v, "mkey": args["name"], "type": args.get("type", "local-ca")}
        pem = await client.get("/api/v2/monitor/system/certificate/download", params)
        if not isinstance(pem, str) or "BEGIN CERTIFICATE" not in pem:
            raise RuntimeError(f"Unexpected response: {str(pem)[:200]}")
        return {"name": args["name"], "sha256_fingerprint": _fingerprint(pem), "pem": pem}

    raise ValueError(f"Unknown tool: {name}")
