"""Logging targets, HA status, FortiTokens and admin MFA."""

import pytest

from fortigate_mcp.tools import config, logs, system
from tests.test_license import EVAL, LICENSE

CMDB = "/api/v2/cmdb"


@pytest.fixture
def captured(monkeypatch):
    """Capture what the wrappers hand to config.set_config instead of running it."""
    calls = []

    async def fake(client, args):
        calls.append(args)
        return {"dry_run": args.get("dry_run", True), "request": "PUT", "changes": args["fields"]}

    monkeypatch.setattr(config, "set_config", fake)
    return calls


async def test_log_targets_flag_cleartext_syslog_and_unverified_faz(fgt):
    c, rec = fgt
    rec.respond("GET", LICENSE, 200, {"results": EVAL})
    rec.respond("GET", f"{CMDB}/log.syslogd2/setting", 200, {"results": {
        "status": "enable", "server": "10.0.0.5", "port": 514, "mode": "udp", "enc-algorithm": "disable"}})
    rec.respond("GET", f"{CMDB}/log.fortianalyzer/setting", 200, {"results": {
        "status": "enable", "server": "10.0.0.9", "certificate-verification": "disable"}})
    rec.respond("GET", f"{CMDB}/log.memory/setting", 200, {"results": {"status": "enable"}})
    out = await logs.handle("get_log_targets", {}, c)
    assert out["syslog"][0]["slot"] == 2 and out["fortianalyzer"][0]["server"] == "10.0.0.9"
    assert {f["check"] for f in out["findings"]} == {"syslog_cleartext", "faz_cert_verification"}


async def test_memory_only_logging_is_flagged(fgt):
    c, rec = fgt
    rec.respond("GET", LICENSE, 200, {"results": EVAL})
    rec.respond("GET", "/api/v2/monitor/system/status", 200, {"results": {"log_disk_status": "not_available"}})
    out = await logs.handle("get_log_targets", {}, c)
    assert [f["check"] for f in out["findings"]] == ["no_remote_logging"]
    assert "lost on reboot" in out["findings"][0]["detail"]


async def test_set_syslog_target_builds_validated_change(fgt, captured):
    c, _ = fgt
    await logs.handle("set_syslog_target", {"server": "10.0.0.5", "slot": 3, "mode": "reliable",
                                           "enc_algorithm": "high", "port": 6514}, c)
    assert captured[-1]["endpoint"] == "log.syslogd3/setting" and captured[-1]["dry_run"] is True
    assert captured[-1]["fields"] == {"status": "enable", "server": "10.0.0.5", "port": 6514, "mode": "reliable",
                                      "enc-algorithm": "high"}
    with pytest.raises(ValueError, match="needs mode reliable"):
        await logs.handle("set_syslog_target", {"server": "10.0.0.5", "enc_algorithm": "high"}, c)
    with pytest.raises(ValueError, match="slot must be 1-4"):
        await logs.handle("set_syslog_target", {"server": "10.0.0.5", "slot": 5}, c)


async def test_ha_cluster_findings(fgt):
    c, rec = fgt
    rec.respond("GET", f"{CMDB}/system/ha", 200, {"results": {
        "mode": "a-p", "group-name": "edge", "hbdev": "port3 50", "encryption": "disable",
        "authentication": "enable", "session-pickup": "disable"}})
    rec.respond("GET", "/api/v2/monitor/system/ha-peer", 200, {"results": [
        {"serial_no": "FGVM01", "hostname": "fgt-a", "priority": 200, "is_manage_primary": True},
        {"serial_no": "FGVM02", "hostname": "fgt-b", "priority": 100}]})
    rec.respond("GET", "/api/v2/monitor/system/ha-checksums", 200, {"results": [
        {"serial_no": "FGVM01", "checksum": {"global": "aa", "root": "bb"}},
        {"serial_no": "FGVM02", "checksum": {"global": "aa", "root": "cc"}}]})
    out = await system.handle("get_ha_status", {}, c)
    assert [m["hostname"] for m in out["members"]] == ["fgt-a", "fgt-b"]
    assert {f["check"] for f in out["findings"]} == {"out_of_sync", "hb_encryption", "single_heartbeat",
                                                      "session_pickup"}


async def test_standalone_ha(fgt):
    c, rec = fgt
    rec.respond("GET", f"{CMDB}/system/ha", 200, {"results": {"mode": "standalone"}})
    out = await system.handle("get_ha_status", {}, c)
    assert out["mode"] == "standalone" and "findings" not in out


async def test_fortitokens_and_admins(fgt):
    c, rec = fgt
    rec.respond("GET", LICENSE, 200, {"results": {"vm": {"status": "vm_valid"}}})
    rec.respond("GET", f"{CMDB}/user/fortitoken", 200, {"results": [{"serial-number": "FTKMOB1", "license": "L1"}]})
    rec.respond("GET", "/api/v2/monitor/user/fortitoken", 200, {"results": {"FTKMOB1": {"status": "active"}}})
    rec.respond("GET", f"{CMDB}/system/admin", 200, {"results": [
        {"name": "ryan", "two-factor": "fortitoken", "fortitoken": "FTKMOB1"},
        {"name": "admin", "two-factor": "disable"}]})
    out = await system.handle("list_fortitokens", {}, c)
    assert out["tokens"] == [{"serial": "FTKMOB1", "status": "active", "license": "L1", "comments": ""}]
    assert out["admins"][0] == {"admin": "ryan", "two_factor": "fortitoken", "token": "FTKMOB1"}
    assert out["admins_without_mfa"] == ["admin"] and "note" not in out


async def test_admin_mfa_checks_prerequisites(fgt, captured):
    c, rec = fgt
    rec.respond("GET", "/api/v2/monitor/user/fortitoken", 200, {"results": {"FTKMOB1": {"status": "active"},
                                                                            "FTKMOB2": {"status": "new"}}})
    out = await system.handle("set_admin_mfa", {"admin": "ryan", "method": "fortitoken", "fortitoken": "FTKMOB1"}, c)
    assert captured[-1]["fields"] == {"two-factor": "fortitoken", "fortitoken": "FTKMOB1"}
    assert "private window" in out["before_you_log_out"]
    with pytest.raises(ValueError, match="isn't active \\(status: new\\)"):
        await system.handle("set_admin_mfa", {"admin": "ryan", "method": "fortitoken", "fortitoken": "FTKMOB2"}, c)
    rec.respond("GET", f"{CMDB}/system/email-server", 200, {"results": {"server": ""}})
    with pytest.raises(ValueError, match="No email server"):
        await system.handle("set_admin_mfa", {"admin": "ryan", "method": "email", "email_to": "r@example.com"}, c)
    with pytest.raises(ValueError, match="method must be one of"):
        await system.handle("set_admin_mfa", {"admin": "ryan", "method": "push"}, c)
