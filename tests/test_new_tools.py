"""Policy security profiles, logs, certificates/SSL profiles and evaluation license activation."""

import base64
import hashlib

import httpx
import pytest

from fortigate_mcp.tools import firewall, logs, security, system

POLICY1 = "/api/v2/cmdb/firewall/policy/1"


async def test_security_profile_auto_enables_utm(fgt):
    c, rec = fgt
    rec.respond("GET", POLICY1, 200, {"results": [{"policyid": 1, "utm-status": "enable",
                                                   "ssl-ssh-profile": "certificate-inspection",
                                                   "application-list": "default"}]})
    out = await firewall.handle(
        "update_firewall_policy",
        {"policyid": 1, "ssl_ssh_profile": "certificate-inspection", "application_list": "default"}, c,
    )
    assert rec.body(0) == {"ssl-ssh-profile": "certificate-inspection", "application-list": "default",
                           "utm-status": "enable"}
    assert "warning" not in out


async def test_ssl_profile_without_security_profile_warns(fgt):
    c, rec = fgt
    rec.respond("GET", POLICY1, 200, {"results": [{"policyid": 1, "utm-status": "disable",
                                                   "ssl-ssh-profile": "deep-inspection"}]})
    out = await firewall.handle("update_firewall_policy", {"policyid": 1, "ssl_ssh_profile": "deep-inspection"}, c)
    assert "no effect" in out["warning"]


async def test_utm_status_explicit_false(fgt):
    c, rec = fgt
    rec.respond("GET", POLICY1, 200, {"results": [{"policyid": 1, "ssl-ssh-profile": "no-inspection"}]})
    await firewall.handle("update_firewall_policy", {"policyid": 1, "utm_status": False, "application_list": ""}, c)
    assert rec.body(0) == {"application-list": "", "utm-status": "disable"}


async def test_logs_validate_type_and_trim_rows(fgt):
    c, rec = fgt
    with pytest.raises(ValueError, match="Unknown log_type"):
        await logs.handle("get_logs", {"log_type": "bogus"}, c)
    rec.respond("GET", "/api/v2/log/memory/app-ctrl", 200, {"results": [
        {"_metadata": {"x": 1}, "srcip": "192.168.150.10", "hostname": "github.com", "app": "HTTPS.BROWSER",
         "sentbyte": 10, "sentbyte_raw_value": "10"}], "total_lines": 1})
    out = await logs.handle("get_logs", {"log_type": "app-ctrl", "rows": 5000, "filter": "srcip==192.168.150.10"}, c)
    params = rec.requests[0].url.params
    assert params["rows"] == "1000" and params["filter"] == "srcip==192.168.150.10"
    assert out["results"] == [{"srcip": "192.168.150.10", "hostname": "github.com", "app": "HTTPS.BROWSER", "sentbyte": 10}]
    out = await logs.handle("get_logs", {"log_type": "app-ctrl", "fields": ["hostname", "missing"]}, c)
    assert out["results"] == [{"hostname": "github.com", "missing": None}]


async def test_list_certificates_flags_weak_and_hides_bundle(fgt):
    c, rec = fgt
    rec.respond("GET", "/api/v2/monitor/system/available-certificates", 200, {"results": [
        {"name": "Fortinet_CA_SSL", "source": "factory", "key_type": "RSA", "key_size": 512},
        {"name": "Fortinet_GUI_Server", "source": "factory", "key_type": "RSA", "key_size": 2048},
        {"name": "Fortinet_SSL_ECDSA256", "source": "factory", "key_type": "ECDSA", "key_size": 256},
        {"name": "ACCVRAIZ1", "source": "bundle", "key_type": "RSA", "key_size": 4096}]})
    out = {r["name"]: r for r in await security.handle("list_certificates", {}, c)}
    assert set(out) == {"Fortinet_CA_SSL", "Fortinet_GUI_Server", "Fortinet_SSL_ECDSA256"}
    assert out["Fortinet_CA_SSL"]["weak"] is True
    assert "weak" not in out["Fortinet_GUI_Server"] and "weak" not in out["Fortinet_SSL_ECDSA256"]


async def test_download_certificate_fingerprint(fgt):
    c, rec = fgt
    der = b"\x30\x03\x02\x01\x01"
    pem = "-----BEGIN CERTIFICATE-----\n" + base64.b64encode(der).decode() + "\n-----END CERTIFICATE-----\n"
    rec.responses[("GET", "/api/v2/monitor/system/certificate/download")] = httpx.Response(200, text=pem)
    out = await security.handle("download_certificate", {"name": "Fortinet_CA_SSL"}, c)
    expected = hashlib.sha256(der).hexdigest().upper()
    assert out["sha256_fingerprint"].replace(":", "") == expected
    assert rec.requests[0].url.params["type"] == "local-ca"


async def test_read_only_ssl_profile_refused(fgt):
    c, rec = fgt
    with pytest.raises(ValueError, match="read-only"):
        await security.handle("update_ssl_ssh_profile", {"name": "deep-inspection", "caname": "X"}, c)
    assert rec.requests == []


async def test_activation_requires_confirm(fgt):
    c, rec = fgt
    with pytest.raises(ValueError, match="confirm=true"):
        await system.handle("activate_vm_eval_license", {"confirm": False}, c)
    assert rec.requests == []


async def test_activation_skips_when_licensed(fgt):
    c, rec = fgt
    rec.respond("GET", "/api/v2/monitor/license/status", 200, {"results": {"vm": {"valid": True, "status": "vm_eval"}}})
    out = await system.handle("activate_vm_eval_license", {"confirm": True}, c)
    assert out["status"] == "already_licensed"
    assert [r.method for r in rec.requests] == ["GET"]


async def test_activation_reads_credentials_from_env_only(monkeypatch, fgt):
    c, rec = fgt
    rec.respond("GET", "/api/v2/monitor/license/status", 200, {"results": {"vm": {"valid": False}}})
    monkeypatch.delenv("FORTICLOUD_ACCOUNT", raising=False)
    monkeypatch.delenv("FORTICLOUD_PASSWORD", raising=False)
    with pytest.raises(ValueError, match="FORTICLOUD_ACCOUNT"):
        await system.handle("activate_vm_eval_license", {"confirm": True, "account_password": "ignored"}, c)
    monkeypatch.setenv("FORTICLOUD_ACCOUNT", "me@example.com")
    monkeypatch.setenv("FORTICLOUD_PASSWORD", "s3cret")
    out = await system.handle("activate_vm_eval_license", {"confirm": True}, c)
    assert out["status"] == "success"
    assert rec.requests[-1].url.path == "/api/v2/monitor/system/vmlicense/download-eval"
    assert rec.body() == {"account_id": "me@example.com", "account_password": "s3cret", "is_government": False}
