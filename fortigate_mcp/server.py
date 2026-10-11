#!/usr/bin/env python3
"""
FortiGate MCP Server

Configuration (environment variables):
    FORTIGATE_HOST        FortiGate hostname or IP (required)
    FORTIGATE_PORT        HTTPS admin port (default: 443)
    FORTIGATE_API_TOKEN   REST API admin token (recommended)
    FORTIGATE_USERNAME    Admin username (alternative to a token)
    FORTIGATE_PASSWORD    Admin password (alternative to a token)
    FORTIGATE_VDOM        VDOM for every call (default: root)
    FORTIGATE_VERIFY_SSL  Verify the TLS certificate: true (default), false, or a CA bundle path
    FORTIGATE_READ_ONLY   Block all writes (POST/PUT/DELETE); GET only (default: false)
    FORTIGATE_TIMEOUT     Request timeout in seconds (default: 30)
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any

import jsonschema
import mcp.server.stdio
from mcp.server import Server, ServerRequestContext
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
    Tool,
)

from . import __version__
from .client import FORTIGATE_READ_ONLY, FortiGateClient, _validate_config
from .integrations import kube as kube_integration
from .integrations import pve as pve_integration
from .tools import (
    appctrl,
    config,
    dns_dhcp,
    firewall,
    fortiguard,
    k8s,
    logs,
    nat,
    network,
    profiles,
    pve,
    raw,
    security,
    system,
    traffic,
)

# --- Build unified tool registry ---

MODULES = [system, fortiguard, firewall, nat, appctrl, profiles, security, traffic, logs, network, dns_dhcp, config, raw]
# Optional integrations: only offered when configured.
if kube_integration.enabled():
    MODULES.append(k8s)
if pve_integration.enabled():
    MODULES.append(pve)

ALL_TOOLS: list[Tool] = []
TOOL_MODULE: dict[str, Any] = {}

for mod in MODULES:
    for tool_def in mod.TOOLS:
        ALL_TOOLS.append(
            Tool(
                name=tool_def["name"],
                description=tool_def["description"],
                inputSchema=tool_def["inputSchema"],
            )
        )
        TOOL_MODULE[tool_def["name"]] = mod

# --- MCP server setup ---

fortigate = FortiGateClient()
SCHEMAS = {t.name: t.input_schema for t in ALL_TOOLS}


def _text(payload: Any, error: bool = False) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=json.dumps(payload, indent=2))], is_error=error)


async def list_tools(ctx: ServerRequestContext, params: PaginatedRequestParams | None) -> ListToolsResult:
    return ListToolsResult(tools=ALL_TOOLS)


async def call_tool(ctx: ServerRequestContext, params: CallToolRequestParams) -> CallToolResult:
    name, arguments = params.name, params.arguments or {}
    try:
        mod = TOOL_MODULE.get(name)
        if mod is None:
            raise ValueError(f"Unknown tool: {name}")
        # mcp 1.x checked arguments against the tool's inputSchema before calling it; 2.x leaves it to us.
        try:
            jsonschema.validate(arguments, SCHEMAS[name])
        except jsonschema.ValidationError as e:
            raise ValueError(f"Input validation error: {e.message}") from None
        return _text(await mod.handle(name, arguments, fortigate))
    except Exception as e:
        return _text({"error": str(e), "tool": name}, error=True)


app = Server("fortigate-mcp-server", version=__version__, on_list_tools=list_tools, on_call_tool=call_tool)


async def main() -> None:
    _validate_config()

    print("=" * 60, file=sys.stderr)
    print("FortiGate MCP Server", file=sys.stderr)
    print(f"Tools: {len(ALL_TOOLS)}" + ("  (read-only)" if FORTIGATE_READ_ONLY else ""), file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    # Close the HTTP client in this event loop: its connections are bound to it.
    try:
        await fortigate.authenticate()

        print(f"✓ Ready — {len(ALL_TOOLS)} tools available", file=sys.stderr)
        print("=" * 60, file=sys.stderr)

        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            await app.run(
                read_stream,
                write_stream,
                app.create_initialization_options(),
            )
    finally:
        await fortigate.close()
        await k8s.aclose()
        await pve_integration.aclose()


def run() -> None:
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n✓ Server stopped", file=sys.stderr)
    except Exception as e:
        print(f"\n✗ Fatal: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    run()
