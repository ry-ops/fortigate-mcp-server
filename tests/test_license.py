"""License awareness: the same tools on the free evaluation VM and on licensed FortiGates."""

import pytest

from fortigate_mcp.tools import system
from fortigate_mcp.tools._license import FortiGateLicenseError, features_report, license_info, parse

LICENSE = "/api/v2/monitor/license/status"
NOW = 1791720000  # 2026-10-11

# Trimmed from the lab FortiGate-VM on the free evaluation license (FortiOS 7.6.7).
EVAL = {
    "fortiguard": {"type": "cloud_service_status", "supported": False, "connected": False},
    "forticare": {"type": "cloud_service_status", "status": "no_support"},
    "antivirus": {"type": "downloaded_fds_object", "status": "no_support", "version": "1.00000",
                  "last_update": 1523318820},
    "ips": {"type": "downloaded_fds_object", "status": "no_support", "version": "6.00741",
            "last_update": 1448958600, "last_update_result_status": "update_result_failed"},
    "web_filtering": {"type": "live_fortiguard_service", "status": "no_support"},
    "vdom": {"type": "platform", "used": 1, "max": 2},
    "vm": {"type": "platform", "valid": True, "status": "vm_eval", "cpu_max": 1},
}

# A licensed VM with a UTP-style bundle; one service about to lapse and one already expired.
PAID = {
    "fortiguard": {"type": "cloud_service_status", "supported": True, "connected": True},
    "antivirus": {"type": "downloaded_fds_object", "status": "licensed", "expires": NOW + 200 * 86400,
                  "version": "92.06811", "last_update": NOW - 3600},
    "ips": {"type": "downloaded_fds_object", "status": "licensed", "expires": NOW + 10 * 86400,
            "version": "29.00954", "last_update": NOW - 7200},
    "web_filtering": {"type": "live_fortiguard_service", "status": "expires_soon", "expires": NOW + 5 * 86400},
    "antispam": {"type": "live_fortiguard_service", "status": "expired", "expires": NOW - 86400},
    "vm": {"type": "platform", "valid": True, "status": "vm_valid", "cpu_max": 8},
}


def test_eval_license_reports_no_services_and_factory_signatures():
    out = features_report(parse(EVAL), now=NOW)
    assert out["edition"] == "FortiGate-VM evaluation (free)"
    assert out["licensed"] == [] and {"ips", "antivirus", "web_filter", "fortiguard"} <= set(out["not_licensed"])
    assert out["signature_databases"]["ips"]["age_days"] > 3000
    assert "evaluation license" in out["note"]


def test_paid_license_lists_services_and_expiry():
    out = features_report(parse(PAID), now=NOW)
    assert out["edition"] == "FortiGate-VM (licensed)"
    assert set(out["licensed"]) == {"antivirus", "ips", "web_filter", "fortiguard"}
    assert out["not_licensed"] == ["antispam"]
    assert {e["feature"] for e in out["expiring_within_30_days"]} == {"ips", "web_filter"}
    assert out["signature_databases"]["antivirus"]["age_days"] == 0
    assert "note" not in out


def test_require_explains_missing_service():
    parse(PAID).require("ips", "Updating IPS sensors")
    with pytest.raises(FortiGateLicenseError, match="free evaluation license.*no_support"):
        parse(EVAL).require("ips", "Updating IPS sensors")
    with pytest.raises(FortiGateLicenseError, match="contract.*expired"):
        parse(PAID).require("antispam", "Email filtering")


async def test_license_is_read_once_and_cached(fgt):
    c, rec = fgt
    rec.respond("GET", LICENSE, 200, {"results": EVAL})
    first = await license_info(c, {})
    again = await license_info(c, {})
    assert first is again and sum(r.url.path == LICENSE for r in rec.requests) == 1
    await license_info(c, {}, refresh=True)
    assert sum(r.url.path == LICENSE for r in rec.requests) == 2


async def test_get_license_features_tool_and_limits_only_on_eval(fgt):
    c, rec = fgt
    rec.respond("GET", LICENSE, 200, {"results": PAID})
    out = await system.handle("get_license_features", {}, c)
    assert out["edition"] == "FortiGate-VM (licensed)"
    limits = await system.handle("get_license_limits", {}, c)
    assert limits["evaluation_limits_apply"] is False and limits["policies"]["limit"] is None
