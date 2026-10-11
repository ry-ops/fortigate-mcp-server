"""The MCP server end to end: an in-process client speaks JSON-RPC to it, as Claude does over stdio."""

import json

import pytest
from mcp.client import Client

from fortigate_mcp import server


@pytest.fixture
def rec(monkeypatch, fgt):
    c, rec = fgt
    monkeypatch.setattr(server, "fortigate", c)
    return rec


def connect() -> Client:
    # Opened inside each test: anyio task groups must close in the task that opened them.
    return Client(server.app, mode="legacy")


async def test_lists_every_tool(rec):
    async with connect() as client:
        tools = (await client.list_tools()).tools
        assert len(tools) == len(server.ALL_TOOLS)
        status = next(t for t in tools if t.name == "get_system_status")
        assert status.input_schema["type"] == "object"


async def test_call_returns_json(rec):
    async with connect() as client:
        rec.respond("GET", "/api/v2/monitor/system/status", 200, {"results": {"hostname": "fgt-lab"}})
        result = await client.call_tool("get_system_status", {})
        assert not result.is_error
        assert json.loads(result.content[0].text)["hostname"] == "fgt-lab"


async def test_status_reports_uptime(rec):
    rec.respond("GET", "/api/v2/monitor/web-ui/state", 200, {"results": {
        "utc_last_reboot": 1791030164000, "snapshot_utc_time": 1791030164000 + (8 * 86400 + 3 * 3600 + 5 * 60) * 1000}})
    async with connect() as client:
        out = json.loads((await client.call_tool("get_system_status", {})).content[0].text)
        assert out["uptime"] == "8d 3h 5m" and out["uptime_seconds"] == 702300
        assert out["last_reboot"] == "2026-10-03T12:22:44Z"


async def test_invalid_arguments_are_refused_before_the_fortigate(rec):
    async with connect() as client:
        result = await client.call_tool("get_address", {})
        assert result.is_error
        assert "Input validation error" in json.loads(result.content[0].text)["error"]
        assert rec.requests == []


async def test_errors_are_flagged(rec):
    async with connect() as client:
        result = await client.call_tool("no_such_tool", {})
        assert result.is_error and json.loads(result.content[0].text) == {"error": "Unknown tool: no_such_tool", "tool": "no_such_tool"}
