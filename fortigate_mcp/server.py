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
    FORTIGATE_VERIFY_SSL  Verify the TLS certificate (default: false)
    FORTIGATE_READ_ONLY   Block all writes (POST/PUT/DELETE); GET only (default: false)
    FORTIGATE_TIMEOUT     Request timeout in seconds (default: 30)
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any

import mcp.server.stdio
from mcp.server import Server
from mcp.types import TextContent, Tool

from .client import FORTIGATE_READ_ONLY, FortiGateClient, _validate_config
from .tools import dns_dhcp, firewall, logs, network, raw, security, system

# --- Build unified tool registry ---

MODULES = [system, firewall, security, logs, network, dns_dhcp, raw]

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
app = Server("fortigate-mcp-server")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return ALL_TOOLS


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    try:
        mod = TOOL_MODULE.get(name)
        if mod is None:
            raise ValueError(f"Unknown tool: {name}")
        result = await mod.handle(name, arguments or {}, fortigate)
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    except Exception as e:
        error = {"error": str(e), "tool": name}
        return [TextContent(type="text", text=json.dumps(error, indent=2))]


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
