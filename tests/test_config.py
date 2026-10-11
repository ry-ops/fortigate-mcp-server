"""Schema-driven tools: endpoint discovery, description, validated writes and monitor reads."""

import httpx
import pytest

from fortigate_mcp.tools import config

# Trimmed from FortiOS 7.6.7's own schema.
LOG_SETTING = {"name": "setting", "category": "complex", "help": "Configure general log settings.", "children": {
    "local-in-deny-unicast": {"name": "local-in-deny-unicast", "category": "unitary", "type": "option",
                              "options": [{"name": "enable"}, {"name": "disable"}], "default": "disable"},
    "resolve-port": {"name": "resolve-port", "category": "unitary", "type": "option",
                     "options": [{"name": "enable"}, {"name": "disable"}]},
}}
LOCAL_IN = {"name": "local-in-policy", "category": "table", "mkey": "policyid", "help": "Configure local-in policies.",
            "children": {
                "policyid": {"name": "policyid", "category": "unitary", "type": "integer", "min-value": 0,
                             "max-value": 4294967295},
                "intf": {"name": "intf", "category": "table", "mkey": "name",
                         "children": {"name": {"name": "name", "type": "string", "size": 79}}},
                "action": {"name": "action", "category": "unitary", "type": "option",
                           "options": [{"name": "accept"}, {"name": "deny"}]},
                "comments": {"name": "comments", "category": "unitary", "type": "var-string", "size": 20},
            }}
ADMIN = {"name": "admin", "category": "table", "mkey": "name", "children": {
    "name": {"name": "name", "type": "string", "size": 64},
    "password": {"name": "password", "type": "password", "size": 128},
    "admintimeout": {"name": "admintimeout", "type": "integer", "min-value": 1, "max-value": 480}}}
SCHEMAS = {"log/setting": LOG_SETTING, "firewall/local-in-policy": LOCAL_IN, "system/admin": ADMIN}
MONITOR_DIR = {"directory": [
    {"path": "system", "name": "ha-peer", "action": "select", "supported": True, "summary": "Get HA peers.",
     "request": {"http_method": "GET", "parameters": [{"name": "serial_no"}]}},
    {"path": "system", "name": "os", "action": "reboot", "supported": True, "summary": "Reboot.",
     "request": {"http_method": "POST"}},
]}


@pytest.fixture
def fgt_schema(fgt):
    """The fgt client, answering ?action=schema requests from SCHEMAS and recording writes."""
    c, rec = fgt
    config_values = {"log/setting": {"local-in-deny-unicast": "disable", "resolve-port": "enable"},
                     "firewall/local-in-policy/2": [{"policyid": 2, "action": "accept", "intf": [{"name": "port1"}]}],
                     "system/admin": [{"name": "admin", "password": "ENC PB2abc", "admintimeout": 5}],
                     "system/admin/admin": [{"name": "admin", "password": "ENC PB2abc", "admintimeout": 5}]}

    def handler(request: httpx.Request) -> httpx.Response:
        rec.requests.append(request)
        path = request.url.path
        if request.url.params.get("action") == "schema":
            if path == "/api/v2/cmdb/":
                return httpx.Response(200, json={"results": [
                    {"path": ep.split("/")[0], "name": ep.split("/")[1], "schema": s} for ep, s in SCHEMAS.items()]})
            if path == "/api/v2/monitor/":
                return httpx.Response(200, json=MONITOR_DIR)
            return httpx.Response(200, json={"results": SCHEMAS[path.removeprefix("/api/v2/cmdb/")]})
        if request.method == "GET" and path.startswith("/api/v2/cmdb/"):
            return httpx.Response(200, json={"results": config_values.get(path.removeprefix("/api/v2/cmdb/"), [])})
        if path == "/api/v2/monitor/system/ha-peer":
            return httpx.Response(200, json={"results": [{"serial_no": "FGVM1"}]})
        return httpx.Response(200, json={"status": "success", "http_status": 200})

    c.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return c, rec


async def test_search_finds_cmdb_and_monitor_endpoints(fgt_schema):
    c, _ = fgt_schema
    out = await config.handle("search_api", {"query": "local-in"}, c)
    assert [r["endpoint"] for r in out["results"]] == ["firewall/local-in-policy"]
    out = await config.handle("search_api", {"query": "ha peer", "kind": "monitor"}, c)
    assert out["results"][0] == {"kind": "monitor", "endpoint": "system/ha-peer", "method": "GET",
                                 "help": "Get HA peers.", "params": ["serial_no"]}


async def test_describe_marks_tables_options_and_secrets(fgt_schema):
    c, _ = fgt_schema
    out = await config.handle("describe_config", {"endpoint": "/api/v2/cmdb/firewall/local-in-policy"}, c)
    assert out["type"] == "table" and out["key"] == "policyid"
    assert out["fields"]["action"]["options"] == ["accept", "deny"]
    assert out["fields"]["intf"] == {"type": "table", "help": "", "key": "name", "fields": ["name"]}
    out = await config.handle("describe_config", {"endpoint": "system/admin", "field": "password"}, c)
    assert out["secret"] is True
    with pytest.raises(ValueError, match="Did you mean: firewall/local-in-policy"):
        await config.handle("describe_config", {"endpoint": "firewall/local-in-policies"}, c)


async def test_set_config_dry_run_shows_change_and_sends_nothing(fgt_schema):
    c, rec = fgt_schema
    out = await config.handle("set_config", {"endpoint": "log/setting",
                                             "fields": {"local-in-deny-unicast": "enable", "resolve-port": "enable"}}, c)
    assert out["dry_run"] is True and out["request"] == "PUT /api/v2/cmdb/log/setting"
    assert out["changes"] == {"local-in-deny-unicast": {"current": "disable", "new": "enable"}}
    assert not any(r.method in ("PUT", "POST", "DELETE") for r in rec.requests)


async def test_set_config_validates_against_schema(fgt_schema):
    c, rec = fgt_schema
    out = await config.handle("set_config", {"endpoint": "firewall/local-in-policy", "mkey": "2", "fields": {
        "action": "allow", "comments": "x" * 30, "acton": "deny"}}, c)
    assert out["valid"] is False
    assert any("allow not one of accept, deny" in e for e in out["errors"])
    assert any("longer than 20" in e for e in out["errors"])
    assert any("unknown field 'acton' (did you mean action" in e for e in out["errors"])
    with pytest.raises(ValueError, match="pass mkey"):
        await config.handle("set_config", {"endpoint": "firewall/local-in-policy", "fields": {"action": "deny"}}, c)
    with pytest.raises(ValueError, match="only update applies"):
        await config.handle("set_config", {"endpoint": "log/setting", "action": "delete"}, c)


async def test_set_config_applies_and_converts_references(fgt_schema):
    c, rec = fgt_schema
    out = await config.handle("set_config", {"endpoint": "firewall/local-in-policy", "action": "create", "mkey": "3",
                                             "fields": {"intf": ["port1"], "action": "deny"}, "dry_run": False}, c)
    assert out["request"] == "POST /api/v2/cmdb/firewall/local-in-policy"
    sent = rec.requests[-1]
    assert sent.method == "POST" and httpx.Response(200, content=sent.content).json() == {
        "intf": [{"name": "port1"}], "action": "deny", "policyid": 3}


async def test_secrets_are_masked_in_reads_and_diffs(fgt_schema):
    c, _ = fgt_schema
    out = await config.handle("get_config", {"endpoint": "system/admin"}, c)
    assert out[0]["password"] == "<set>"
    out = await config.handle("set_config", {"endpoint": "system/admin", "mkey": "admin",
                                             "fields": {"password": "hunter2-new"}}, c)
    assert out["changes"]["password"] == {"current": "<set>", "new": "<set>"}
    assert "hunter2" not in str(out) and "PB2abc" not in str(out)


async def test_get_monitor_reads_get_endpoints_only(fgt_schema):
    c, _ = fgt_schema
    assert await config.handle("get_monitor", {"endpoint": "system/ha-peer"}, c) == [{"serial_no": "FGVM1"}]
    with pytest.raises(ValueError, match="POST endpoint that acts"):
        await config.handle("get_monitor", {"endpoint": "system/os/reboot"}, c)
    with pytest.raises(ValueError, match="takes serial_no; not bogus"):
        await config.handle("get_monitor", {"endpoint": "system/ha-peer", "params": {"bogus": 1}}, c)
