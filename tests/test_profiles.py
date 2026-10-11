"""Security profiles and whether accept policies actually use them."""

from fortigate_mcp.tools import profiles
from tests.test_license import EVAL, LICENSE

POLICIES = "/api/v2/cmdb/firewall/policy"
IFACES = "/api/v2/cmdb/system/interface"
LICENSED = {"fortiguard": {"supported": True, "connected": True}, "ips": {"status": "licensed"},
            "antivirus": {"status": "expired"}, "appctrl": {"status": "licensed"},
            "vm": {"status": "vm_valid"}}

# The lab FortiGate's three policies, plus two that show the other checks.
LAB_POLICIES = [
    {"policyid": 1, "name": "LAB-EGRESS", "action": "accept", "status": "enable", "srcintf": [{"name": "port2"}],
     "dstintf": [{"name": "port1"}], "utm-status": "enable", "ssl-ssh-profile": "certificate-inspection",
     "application-list": "default", "logtraffic": "all"},
    {"policyid": 2, "name": "HOME-to-K3S-MGMT", "action": "accept", "status": "enable", "srcintf": [{"name": "port1"}],
     "dstintf": [{"name": "port2"}], "utm-status": "disable", "ssl-ssh-profile": "no-inspection", "logtraffic": "all"},
    {"policyid": 3, "name": "WEB-IN", "action": "accept", "status": "enable", "srcintf": [{"name": "port1"}],
     "dstintf": [{"name": "port2"}], "utm-status": "disable", "ips-sensor": "default", "logtraffic": "disable"},
    {"policyid": 4, "name": "SCAN-OUT", "action": "accept", "status": "enable", "srcintf": [{"name": "port2"}],
     "dstintf": [{"name": "port1"}], "utm-status": "enable", "ssl-ssh-profile": "certificate-inspection",
     "ips-sensor": "default", "av-profile": "default", "logtraffic": "all"},
    {"policyid": 5, "name": "BLOCK", "action": "deny", "status": "enable", "srcintf": [{"name": "port1"}],
     "dstintf": [{"name": "port2"}]},
]


def _setup(rec, lic):
    rec.respond("GET", LICENSE, 200, {"results": lic})
    rec.respond("GET", POLICIES, 200, {"results": LAB_POLICIES})
    rec.respond("GET", IFACES, 200, {"results": [{"name": "port1", "role": "wan"}, {"name": "port2", "role": "lan"}]})


async def test_list_profiles_shows_users_and_license(fgt):
    c, rec = fgt
    _setup(rec, EVAL)
    rec.respond("GET", "/api/v2/cmdb/ips/sensor", 200, {"results": [{"name": "default", "comment": "Prevent critical"},
                                                                     {"name": "high_security", "comment": ""}]})
    out = await profiles.handle("list_security_profiles", {"kind": "ips"}, c)
    assert out["ips"]["license"] == "not licensed (no_support)" and "bundled" in out["ips"]["without_license"]
    assert out["ips"]["profiles"] == [
        {"name": "default", "comment": "Prevent critical", "used_by": ["3:WEB-IN", "4:SCAN-OUT"]},
        {"name": "high_security", "comment": "", "used_by": []}]


async def test_audit_on_licensed_unit(fgt):
    c, rec = fgt
    _setup(rec, LICENSED)
    out = await profiles.handle("audit_policy_protection", {}, c)
    got = {(f["severity"], f["check"], f["policy"]) for f in out["findings"]}
    assert got == {
        ("warn", "no_ips", "2:HOME-to-K3S-MGMT"),
        ("warn", "no_ips", "3:WEB-IN"),            # sensor attached but security profiles disabled
        ("warn", "profiles_ignored", "3:WEB-IN"),
        ("info", "no_logging", "3:WEB-IN"),
        ("info", "no_ips", "1:LAB-EGRESS"),
        ("warn", "unlicensed_profile", "4:SCAN-OUT"),  # antivirus expired
        ("info", "https_not_inspected", "4:SCAN-OUT"),
    }
    assert [p["direction"] for p in out["policies"]] == ["outbound", "inbound", "inbound", "outbound"]
    assert "note" not in out


async def test_audit_on_eval_marks_unlicensed_profiles_as_expected(fgt):
    c, rec = fgt
    _setup(rec, EVAL)
    out = await profiles.handle("audit_policy_protection", {}, c)
    unlicensed = [f for f in out["findings"] if f["check"] == "unlicensed_profile"]
    assert {f["severity"] for f in unlicensed} == {"info"} and "evaluation license" in out["note"]
