"""Tool handlers build the request bodies FortiOS expects."""

import pytest

from fortigate_mcp.tools import dns_dhcp, firewall, network, raw
from fortigate_mcp.tools._common import subnet


def test_subnet_converts_cidr():
    assert subnet("192.168.150.0/24") == "192.168.150.0 255.255.255.0"
    assert subnet("10.0.0.50/32") == "10.0.0.50 255.255.255.255"
    assert subnet("10.0.0.0 255.0.0.0") == "10.0.0.0 255.0.0.0"


async def test_create_policy_body(fgt):
    c, rec = fgt
    await firewall.handle(
        "create_firewall_policy",
        {"name": "HOME-to-TRAEFIK", "srcintf": ["port1"], "dstintf": ["port2"], "srcaddr": ["HOME-NETS"],
         "dstaddr": ["K3S-NODES"], "service": ["HTTP", "HTTPS"], "nat": False},
        c,
    )
    b = rec.body()
    assert b["srcintf"] == [{"name": "port1"}]
    assert b["service"] == [{"name": "HTTP"}, {"name": "HTTPS"}]
    assert b["nat"] == "disable"
    assert b["action"] == "accept" and b["schedule"] == "always"


async def test_update_policy_only_sends_given_fields(fgt):
    c, rec = fgt
    await firewall.handle("update_firewall_policy", {"policyid": 2, "srcaddr": ["ADMIN-DEVICES"]}, c)
    assert rec.requests[0].method == "PUT"
    assert rec.requests[0].url.path == "/api/v2/cmdb/firewall/policy/2"
    assert rec.body() == {"srcaddr": [{"name": "ADMIN-DEVICES"}]}


async def test_move_policy_requires_one_anchor(fgt):
    c, _ = fgt
    with pytest.raises(ValueError, match="exactly one"):
        await firewall.handle("move_firewall_policy", {"policyid": 3}, c)


async def test_move_policy_params(fgt):
    c, rec = fgt
    await firewall.handle("move_firewall_policy", {"policyid": 3, "before": 1}, c)
    params = rec.requests[0].url.params
    assert params["action"] == "move" and params["before"] == "1"


async def test_address_range_and_cidr(fgt):
    c, rec = fgt
    await firewall.handle("create_address", {"name": "K3S-NODES", "start_ip": "192.168.150.10", "end_ip": "192.168.150.12"}, c)
    assert rec.body() == {"name": "K3S-NODES", "type": "iprange", "start-ip": "192.168.150.10", "end-ip": "192.168.150.12"}
    await firewall.handle("create_address", {"name": "LAB-NET", "subnet": "192.168.150.0/24"}, c)
    assert rec.body()["subnet"] == "192.168.150.0 255.255.255.0"


async def test_address_name_is_url_quoted(fgt):
    c, rec = fgt
    await firewall.handle("delete_address", {"name": "web servers/a"}, c)
    assert rec.requests[0].url.raw_path.startswith(b"/api/v2/cmdb/firewall/address/web%20servers%2Fa")


async def test_dhcp_reservation_uses_reserved_action(fgt):
    c, rec = fgt
    rec.respond("GET", "/api/v2/cmdb/system.dhcp/server/1/reserved-address", 200,
                {"results": [{"id": 1}, {"id": 2}]})
    await dns_dhcp.handle("add_dhcp_reservation", {"server_id": 1, "mac": "BC:24:11:00:00:01", "ip": "192.168.150.10"}, c)
    b = rec.body()
    assert b == {"id": 3, "type": "mac", "mac": "bc:24:11:00:00:01", "action": "reserved", "ip": "192.168.150.10"}


async def test_wildcard_dns_record_rejected_before_any_request(fgt):
    c, rec = fgt
    with pytest.raises(ValueError, match="wildcard"):
        await dns_dhcp.handle("add_dns_record", {"zone": "lab", "hostname": "*", "ip": "192.168.150.10"}, c)
    assert rec.requests == []


async def test_set_dns_server_creates_when_missing(fgt):
    c, rec = fgt
    rec.respond("PUT", "/api/v2/cmdb/system/dns-server/port2", 404, {"status": "error", "http_status": 404})
    await dns_dhcp.handle("set_dns_server", {"interface": "port2"}, c)
    assert [r.method for r in rec.requests] == ["PUT", "POST"]
    assert rec.body() == {"name": "port2", "mode": "recursive"}


async def test_static_route_converts_cidr(fgt):
    c, rec = fgt
    await network.handle("create_static_route", {"dst": "0.0.0.0/0", "gateway": "10.0.0.1", "device": "port1"}, c)
    assert rec.body() == {"dst": "0.0.0.0 0.0.0.0", "device": "port1", "gateway": "10.0.0.1"}


async def test_raw_rejects_paths_outside_api(fgt):
    c, _ = fgt
    with pytest.raises(ValueError, match="/api/v2/"):
        await raw.handle("fortigate_api", {"method": "GET", "path": "/logincheck"}, c)


async def test_backup_allowed_in_read_only_and_written_to_file(monkeypatch, fgt, tmp_path):
    from fortigate_mcp import client as client_mod
    from fortigate_mcp.tools import system

    c, rec = fgt
    monkeypatch.setattr(client_mod, "FORTIGATE_READ_ONLY", True)
    conf = '#config-version=FGVMK6-7.6.7\nconfig system global\n    set alias "x"\n    set hostname "fgt-lab"\nend\n'
    rec.responses[("POST", "/api/v2/monitor/system/config/backup")] = __import__("httpx").Response(200, text=conf)
    out = await system.handle("backup_config", {"output_path": str(tmp_path / "b.conf")}, c)
    assert (tmp_path / "b.conf").read_text() == conf
    assert out["bytes"] == len(conf) and out["config_version"].startswith("#config-version")
    assert rec.body() == {"destination": "file", "scope": "global"}


async def test_resource_usage_keeps_current_values(fgt):
    from fortigate_mcp.tools import system

    c, rec = fgt
    rec.respond("GET", "/api/v2/monitor/system/resource/usage", 200,
                {"results": {"cpu": [{"current": 3, "historical": {"1-min": {"values": [[1, 2]]}}}],
                             "mem": [{"current": 71}]}})
    assert await system.handle("get_resource_usage", {}, c) == {"cpu": 3, "mem": 71}


async def test_sessions_uses_plural_endpoint(fgt):
    c, rec = fgt
    rec.respond("GET", "/api/v2/monitor/firewall/sessions", 200, {"results": {"details": [{"saddr": "a"}]}})
    assert await firewall.handle("list_sessions", {"dstport": 443}, c) == [{"saddr": "a"}]
    assert rec.requests[0].url.params["dstport"] == "443"


async def test_forticonverter_prompt_read_only_by_default(fgt):
    from fortigate_mcp.tools import system

    c, rec = fgt
    rec.respond("GET", "/api/v2/monitor/forticonverter/show-in-startup", 200, {"results": {"hidden": False}})
    assert await system.handle("forticonverter_setup_prompt", {}, c) == {"hidden": False}
    assert [r.method for r in rec.requests] == ["GET"]


async def test_forticonverter_prompt_hide_posts_then_reads(fgt):
    from fortigate_mcp.tools import system

    c, rec = fgt
    rec.respond("GET", "/api/v2/monitor/forticonverter/show-in-startup", 200, {"results": {"hidden": True}})
    out = await system.handle("forticonverter_setup_prompt", {"hide": True}, c)
    assert rec.requests[0].method == "POST"
    assert rec.requests[0].url.path == "/api/v2/monitor/forticonverter/show-in-startup/set"
    assert rec.body(0) == {"hide": True}
    assert out == {"hidden": True}
