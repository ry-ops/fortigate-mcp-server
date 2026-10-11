"""FortiGuard and firmware tools on the free evaluation VM and on a licensed unit."""

import time

import pytest

from fortigate_mcp.tools import fortiguard
from fortigate_mcp.tools._license import FortiGateLicenseError
from tests.test_license import EVAL, LICENSE

NOW = time.time()
SERVERS = "/api/v2/monitor/system/fortiguard/server-info"
FIRMWARE = "/api/v2/monitor/system/firmware"
PATHS = "/api/v2/monitor/system/firmware/upgrade-paths"
SCHEDULE = "/api/v2/cmdb/system.autoupdate/schedule"
SETTINGS = "/api/v2/cmdb/system/fortiguard"
UPDATE = "/api/v2/monitor/system/fortiguard/update"

LICENSED = {
    "fortiguard": {"supported": True, "connected": True},
    "ips": {"status": "licensed", "version": "29.00954", "last_update": NOW - 20 * 86400},
    "antivirus": {"status": "licensed", "version": "92.06811", "last_update": NOW - 3600},
    "vm": {"status": "vm_valid"},
}
CURRENT = {"version": "v7.4.7", "major": 7, "minor": 4, "patch": 7, "build": 2731, "maturity": "M"}


def _common(rec, lic, servers):
    rec.respond("GET", LICENSE, 200, {"results": lic})
    rec.respond("GET", SERVERS, 200, {"results": servers})
    rec.respond("GET", SCHEDULE, 200, {"results": {"status": "disable", "frequency": "daily"}})
    rec.respond("GET", SETTINGS, 200, {"results": {"protocol": "https", "auto-firmware-upgrade": "enable",
                                                   "webfilter-cache": "enable"}})


async def test_eval_unit_explains_instead_of_alarming(fgt):
    c, rec = fgt
    _common(rec, EVAL, {"12.34.97.18": {"status": {"fail": True}, "packets": 56, "current_lost": 53}})
    out = await fortiguard.handle("get_fortiguard_status", {}, c)
    assert out["servers"] == [{"server": "12.34.97.18", "failing": True, "rtt_ms": None, "packet_loss_pct": 95}]
    assert out["findings"] == [] and "expected, not a fault" in out["note"]
    assert out["settings"] == {"protocol": "https", "auto-firmware-upgrade": "enable"}
    with pytest.raises(FortiGateLicenseError, match="needs a FortiGuard subscription"):
        await fortiguard.handle("update_fortiguard", {}, c)


async def test_licensed_unit_flags_stale_signatures_failing_servers_and_schedule(fgt):
    c, rec = fgt
    _common(rec, LICENSED, {"a": {"status": {"fail": True}, "packets": 10, "current_lost": 10},
                            "b": {"status": {"fail": False}, "packets": 10, "current_lost": 0}})
    out = await fortiguard.handle("get_fortiguard_status", {}, c)
    got = {(f["severity"], f["check"]) for f in out["findings"]}
    assert got == {("warn", "fortiguard_servers"), ("warn", "stale_signatures"), ("warn", "update_schedule")}
    assert "ips signatures are 20 days old" in str(out["findings"]) and "note" not in out


async def test_update_dry_run_then_apply(fgt):
    c, rec = fgt
    rec.respond("GET", LICENSE, 200, {"results": LICENSED})
    out = await fortiguard.handle("update_fortiguard", {}, c)
    assert out["dry_run"] is True and out["signature_age_days"]["ips"] == 20
    assert not any(r.method == "POST" for r in rec.requests)
    out = await fortiguard.handle("update_fortiguard", {"dry_run": False}, c)
    assert out["status"] == "requested" and any(r.method == "POST" and r.url.path == UPDATE for r in rec.requests)


async def test_firmware_lists_newer_images_in_order(fgt):
    c, rec = fgt
    rec.respond("GET", LICENSE, 200, {"results": LICENSED})
    rec.respond("GET", FIRMWARE, 200, {"results": {"current": CURRENT, "available": [
        {"version": "v7.6.7", "major": 7, "minor": 6, "patch": 7, "build": 3704, "id": "a"},
        {"version": "v7.4.6", "major": 7, "minor": 4, "patch": 6, "build": 2726, "id": "old"},
        {"version": "v7.4.8", "major": 7, "minor": 4, "patch": 8, "build": 2795, "id": "b"}]}})
    rec.respond("GET", PATHS, 200, {"results": [{"from": "7.4.7", "to": "7.6.7"}]})
    rec.respond("GET", SETTINGS, 200, {"results": {"auto-firmware-upgrade": "disable"}})
    out = await fortiguard.handle("get_firmware_status", {}, c)
    assert [i["version"] for i in out["newer_images"]] == ["v7.4.8", "v7.6.7"]
    assert out["latest"]["version"] == "v7.6.7" and out["upgrade_path"] == [{"from": "7.4.7", "to": "7.6.7"}]
    assert out["auto_firmware_upgrade"] == {"auto-firmware-upgrade": "disable"} and "note" not in out


async def test_firmware_on_eval_survives_upgrade_path_error(fgt):
    c, rec = fgt
    rec.respond("GET", LICENSE, 200, {"results": EVAL})
    rec.respond("GET", FIRMWARE, 200, {"results": {"current": CURRENT, "available": []}})
    rec.respond("GET", PATHS, 500, {"status": "error", "http_status": 500})
    out = await fortiguard.handle("get_firmware_status", {}, c)
    assert out["current"]["version"] == "v7.4.7" and out["newer_images"] == []
    assert "HTTP 500" in out["upgrade_path_error"] and "evaluation license" in out["note"]
