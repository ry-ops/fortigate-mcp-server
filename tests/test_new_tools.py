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


async def test_get_logs_scopes_event_subtype_and_drops_strays(fgt):
    c, rec = fgt
    rec.respond("GET", "/api/v2/log/memory/event/vpn", 200, {"percent_logs_processed": 6, "results": [
        {"subtype": "system", "logdesc": "System performance statistics"},
        {"subtype": "vpn", "action": "info", "logdesc": "Certificate removed"}]})
    out = await logs.handle("get_logs", {"log_type": "event/vpn", "filter": "action==info"}, c)
    assert rec.requests[0].url.params.get_list("filter") == ["subtype==vpn", "action==info"]
    assert [r["logdesc"] for r in out["results"]] == ["Certificate removed"]
    assert any("don't match" in w for w in out["warnings"]) and any("6%" in w for w in out["warnings"])


async def test_get_logs_ands_a_list_and_refuses_filters_fortios_ignores(fgt):
    c, rec = fgt
    await logs.handle("get_logs", {"log_type": "traffic/forward", "filter": ["dstport==4332,dstport==4432", "srcip==10.0.0.5"]}, c)
    assert rec.requests[0].url.params.get_list("filter") == ["dstport==4332,dstport==4432", "srcip==10.0.0.5"]
    for bad, msg in (("dstip==1.2.3.4,dstport==4332", "different fields"), ("srcip==1.2.3.4&dstport==443", "'&'")):
        with pytest.raises(ValueError, match=msg):
            await logs.handle("get_logs", {"log_type": "traffic/forward", "filter": bad}, c)
    assert len(rec.requests) == 1


async def test_get_logs_logid_filter_accepts_short_form(fgt):
    c, rec = fgt
    rec.respond("GET", "/api/v2/log/memory/event/system", 200, {"results": [{"subtype": "system", "logid": "0100032001"}]})
    out = await logs.handle("get_logs", {"log_type": "event/system", "filter": "logid==32001"}, c)
    assert out["rows"] == 1 and "warnings" not in out


AUDIT_CONF = """#config-version=FGVMK6-7.6.7
config system admin
    edit "admin"
        set old-password ENC SH2abcdef
        set accprofile "super_admin"
        config gui-dashboard
            edit 1
                set name "Status"
            next
        end
        set password ENC PB2abcdef
    next
    edit "stale"
        set accprofile "super_admin"
        set password ENC SH2ghijkl
    next
end
"""


def _audit_responses(rec, version="v7.6.7"):
    rec.respond("GET", "/api/v2/monitor/system/status", 200, {"version": version, "results": {}})
    rec.respond("GET", "/api/v2/cmdb/system/admin", 200, {"results": [
        {"name": "admin", "trusthost1": "0.0.0.0 0.0.0.0", "two-factor": "disable", "remote-auth": "disable"},
        {"name": "stale", "trusthost1": "10.0.0.0 255.255.255.0", "two-factor": "fortitoken"}]})
    rec.respond("GET", "/api/v2/cmdb/system/api-user", 200, {"results": [
        {"name": "ci", "accprofile": "super_admin", "trusthost": []}]})
    rec.respond("GET", "/api/v2/cmdb/system/interface", 200, {"results": [
        {"name": "port1", "role": "wan", "ip": "203.0.113.5 255.255.255.0", "allowaccess": "ping https ssh"},
        {"name": "port2", "role": "lan", "ip": "192.168.1.1 255.255.255.0", "allowaccess": "ping https http"}]})
    rec.respond("GET", "/api/v2/cmdb/system/password-policy", 200, {"results": {
        "login-lockout-upon-weaker-encryption": "disable"}})
    rec.responses[("POST", "/api/v2/monitor/system/config/backup")] = httpx.Response(200, text=AUDIT_CONF)


async def test_audit_admin_access_grades_findings(fgt):
    c, rec = fgt
    _audit_responses(rec)
    out = await system.handle("audit_admin_access", {}, c)
    got = {(f["severity"], f["check"], f["object"]) for f in out["findings"]}
    assert got == {
        ("critical", "wan_admin_access", "port1"),
        ("critical", "api_user_trusthosts", "ci"),
        ("warn", "admin_trusthosts", "admin"),
        ("warn", "admin_mfa", "admin"),
        ("warn", "legacy_hash", "admin"),
        ("warn", "legacy_hash", "stale"),
        ("warn", "cleartext_admin", "port2"),
        ("info", "default_admin", "admin"),
        ("info", "api_user_profile", "ci"),
    }
    assert [f["severity"] for f in out["findings"]][:2] == ["critical", "critical"]
    assert out["summary"] == {"critical": 2, "warn": 5, "info": 2}
    assert "SH2abcdef" not in str(out)


async def test_audit_admin_access_flags_sha256_firmware_and_can_skip_backup(fgt):
    c, rec = fgt
    _audit_responses(rec, version="v7.4.7")
    out = await system.handle("audit_admin_access", {"check_hashes": False}, c)
    assert ("critical", "password_hashing") in {(f["severity"], f["check"]) for f in out["findings"]}
    assert not any(r.method == "POST" for r in rec.requests)


def test_pbkdf2_version_cutoffs():
    from fortigate_mcp.tools.system import _supports_pbkdf2

    assert not _supports_pbkdf2((7, 2, 10)) and _supports_pbkdf2((7, 2, 11))
    assert not _supports_pbkdf2((7, 4, 7)) and _supports_pbkdf2((7, 4, 8))
    assert not _supports_pbkdf2((7, 6, 0)) and _supports_pbkdf2((7, 6, 1))
    assert _supports_pbkdf2((8, 0, 0)) and not _supports_pbkdf2((7, 0, 17))
