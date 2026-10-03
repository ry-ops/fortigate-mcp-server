"""License limits, port forwards, FortiView, app control and service groups."""

import pytest

from fortigate_mcp.client import FortiGateAPIError
from fortigate_mcp.tools import appctrl, firewall, nat, system, traffic

LICENSE = "/api/v2/monitor/license/status"
POLICIES = "/api/v2/cmdb/firewall/policy"
VIPS = "/api/v2/cmdb/firewall/vip"


def eval_state(rec, policies=3, vm_status="vm_eval"):
    rec.respond("GET", LICENSE, 200, {"results": {"vm": {"status": vm_status, "cpu_used": 1, "cpu_max": 1}}})
    rec.respond("GET", POLICIES, 200, {"results": [{"policyid": i, "name": f"P{i}", "dstaddr": []} for i in range(1, policies + 1)]})
    rec.respond("GET", "/api/v2/cmdb/router/static", 200, {"results": []})
    rec.respond("GET", "/api/v2/cmdb/system/interface", 200, {"results": [
        {"name": "port1", "type": "physical", "ip": "0.0.0.0 0.0.0.0", "mode": "dhcp"},
        {"name": "port2", "type": "physical", "ip": "192.168.150.1 255.255.255.0", "mode": "static"},
        {"name": "port3", "type": "physical", "ip": "0.0.0.0 0.0.0.0", "mode": "static"},
        {"name": "fortilink", "type": "aggregate", "ip": "10.255.1.1 255.255.255.0"},
        {"name": "ssl.root", "type": "tunnel", "ip": "0.0.0.0 0.0.0.0"},
    ]})


async def test_license_limits_count_eval_objects(fgt):
    c, rec = fgt
    eval_state(rec)
    out = await system.handle("get_license_limits", {}, c)
    assert out["evaluation_limits_apply"] is True
    assert out["policies"]["used"] == 3 and out["policies"]["free"] == 0
    assert out["interfaces"]["items"] == ["port1", "port2"]  # unused port3 and built-ins excluded
    assert out["static_routes"] == {"used": 0, "limit": 3, "items": [], "free": 3}


async def test_license_limits_absent_on_paid_license(fgt):
    c, rec = fgt
    eval_state(rec, vm_status="vm_valid")
    out = await system.handle("get_license_limits", {}, c)
    assert out["evaluation_limits_apply"] is False and out["policies"]["limit"] is None


VIP_ARGS = {"name": "VIP-WEB", "extintf": "port1", "mappedip": "192.168.150.10", "extport": "8443", "mappedport": "443"}


async def test_port_forward_refuses_mixing_before_creating(fgt):
    c, rec = fgt
    rec.respond("GET", f"{POLICIES}/3", 200, {"results": [{"policyid": 3, "srcintf": [{"name": "port1"}], "dstaddr": [{"name": "K3S-NODES"}]}]})
    rec.respond("GET", VIPS, 200, {"results": []})
    with pytest.raises(ValueError, match="cannot mix"):
        await nat.handle("create_port_forward", {**VIP_ARGS, "attach_to_policy": 3}, c)
    assert not any(r.method == "POST" for r in rec.requests)


async def test_port_forward_wrong_interface(fgt):
    c, rec = fgt
    rec.respond("GET", f"{POLICIES}/1", 200, {"results": [{"policyid": 1, "srcintf": [{"name": "port2"}], "dstaddr": []}]})
    with pytest.raises(ValueError, match="does not take traffic from port1"):
        await nat.handle("create_port_forward", {**VIP_ARGS, "attach_to_policy": 1}, c)


async def test_port_forward_replace_destinations_attaches(fgt):
    c, rec = fgt
    rec.respond("GET", f"{POLICIES}/3", 200, {"results": [{"policyid": 3, "srcintf": [{"name": "port1"}],
                                                          "dstaddr": [{"name": "K3S-NODES"}, {"name": "VIP-OLD"}]}]})
    rec.respond("GET", VIPS, 200, {"results": [{"name": "VIP-OLD"}]})
    out = await nat.handle("create_port_forward", {**VIP_ARGS, "attach_to_policy": 3, "replace_destinations": True}, c)
    vip_body = next(rec.body(i) for i, r in enumerate(rec.requests) if r.method == "POST")
    assert vip_body["mappedip"] == [{"range": "192.168.150.10"}] and vip_body["mappedport"] == "443"
    assert rec.body() == {"dstaddr": [{"name": "VIP-OLD"}, {"name": "VIP-WEB"}]}
    assert out["replaced_destinations"] == ["K3S-NODES"]


async def test_port_forward_rolls_back_vip_when_policy_refuses(fgt):
    c, rec = fgt
    rec.respond("GET", f"{POLICIES}/3", 200, {"results": [{"policyid": 3, "srcintf": [{"name": "port1"}], "dstaddr": []}]})
    rec.respond("PUT", f"{POLICIES}/3", 500, {"status": "error", "cli_error": ["boom"]})
    with pytest.raises(FortiGateAPIError, match="boom"):
        await nat.handle("create_port_forward", {**VIP_ARGS, "attach_to_policy": 3}, c)
    assert [r.method for r in rec.requests][-2:] == ["PUT", "DELETE"]
    assert rec.requests[-1].url.path == f"{VIPS}/VIP-WEB"


async def test_port_forward_without_policy_notes_full_eval(fgt):
    c, rec = fgt
    eval_state(rec)
    out = await nat.handle("create_port_forward", VIP_ARGS, c)
    assert "all in use" in out["note"]


async def test_delete_port_forward_detaches(fgt):
    c, rec = fgt
    rec.respond("GET", POLICIES, 200, {"results": [{"policyid": 3, "dstaddr": [{"name": "VIP-WEB"}, {"name": "VIP-B"}]}]})
    with pytest.raises(ValueError, match="detach=true"):
        await nat.handle("delete_port_forward", {"name": "VIP-WEB"}, c)
    out = await nat.handle("delete_port_forward", {"name": "VIP-WEB", "detach": True}, c)
    puts = [i for i, r in enumerate(rec.requests) if r.method == "PUT"]
    assert rec.body(puts[-1]) == {"dstaddr": [{"name": "VIP-B"}]}
    assert out["detached_from_policies"] == [3]


async def test_top_traffic_resolves_app_names(fgt):
    c, rec = fgt
    traffic._app_names.clear()
    rec.respond("GET", "/api/v2/monitor/fortiview/realtime-statistics", 200, {"results": {"details": [
        {"srcaddr": "192.168.150.11", "resolved": "speed.cloudflare.com", "rcvdbyte": 99, "apps": [{"id": 40568}]}]}})
    rec.respond("GET", "/api/v2/cmdb/application/name", 200, {"results": [{"id": 40568, "name": "HTTPS.BROWSER"}]})
    out = await traffic.handle("get_top_traffic", {"report_by": "destination", "srcaddr": "192.168.150.11"}, c)
    assert out == [{"srcaddr": "192.168.150.11", "resolved": "speed.cloudflare.com", "rcvdbyte": 99,
                    "applications": ["HTTPS.BROWSER"]}]
    assert rec.requests[0].url.params["srcaddr"] == '{"value":"192.168.150.11"}'
    with pytest.raises(ValueError, match="report_by"):
        await traffic.handle("get_top_traffic", {"report_by": "nonsense"}, c)


async def test_arp_filter(fgt):
    c, rec = fgt
    rec.respond("GET", "/api/v2/monitor/network/arp", 200, {"results": [
        {"ip": "10.88.145.1", "interface": "port1"}, {"ip": "192.168.150.10", "interface": "port2"}]})
    assert await traffic.handle("get_arp_table", {"interface": "port2"}, c) == [{"ip": "192.168.150.10", "interface": "port2"}]


CATS = {"results": [{"id": 2, "name": "P2P"}, {"id": 5, "name": "Video/Audio"}]}


async def test_app_rule_inserted_at_top_by_name(fgt):
    c, rec = fgt
    rec.respond("GET", "/api/v2/monitor/utm/application-categories", 200, CATS)
    rec.respond("GET", "/api/v2/cmdb/application/name", 200, {"results": [{"id": 31077, "name": "YouTube"}]})
    rec.respond("GET", "/api/v2/cmdb/application/list/default", 200, {"results": [{"name": "default", "entries": [{"id": 1}]}]})
    out = await appctrl.handle("add_app_control_rule",
                               {"profile": "default", "applications": ["YouTube"], "categories": ["p2p"], "action": "block"}, c)
    post = next(i for i, r in enumerate(rec.requests) if r.method == "POST")
    assert rec.body(post) == {"id": 2, "action": "block", "log": "enable",
                              "application": [{"id": 31077}], "category": [{"id": 2}]}
    move = rec.requests[-1]
    assert move.method == "PUT" and move.url.params["action"] == "move" and move.url.params["before"] == "1"
    assert out["rule_id"] == 2 and out["position"] == "top"


async def test_app_rule_bottom_warns_when_shadowed(fgt):
    c, rec = fgt
    rec.respond("GET", "/api/v2/monitor/utm/application-categories", 200, CATS)
    rec.respond("GET", "/api/v2/cmdb/application/list/default", 200, {"results": [{"entries": [{"id": 1, "application": [], "category": []}]}]})
    out = await appctrl.handle("add_app_control_rule", {"profile": "default", "categories": ["5"], "position": "bottom"}, c)
    assert "never be reached" in out["warning"]


async def test_app_unknown_category_lists_known(fgt):
    c, rec = fgt
    rec.respond("GET", "/api/v2/monitor/utm/application-categories", 200, CATS)
    with pytest.raises(ValueError, match="known: P2P, Video/Audio"):
        await appctrl.handle("search_applications", {"category": "Gamez"}, c)


async def test_service_group_create(fgt):
    c, rec = fgt
    await firewall.handle("create_service_group", {"name": "K3S-MGMT", "members": ["SSH", "K8S-API", "PING"]}, c)
    assert rec.body() == {"name": "K3S-MGMT", "member": [{"name": "SSH"}, {"name": "K8S-API"}, {"name": "PING"}]}
