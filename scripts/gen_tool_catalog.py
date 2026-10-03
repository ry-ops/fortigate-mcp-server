#!/usr/bin/env python3
"""Generate the README tool catalog between <!-- TOOLS:START --> and <!-- TOOLS:END -->.

The catalog is built from every tool module, including the optional Kubernetes and Proxmox ones,
so it never drifts from the code. Run: python3 scripts/gen_tool_catalog.py  (or --check in CI)
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fortigate_mcp.tools import (  # noqa: E402
    appctrl,
    dns_dhcp,
    firewall,
    k8s,
    logs,
    nat,
    network,
    pve,
    raw,
    security,
    system,
    traffic,
)

AREAS = [
    ("System, license and interfaces", system),
    ("Firewall policies, addresses and services", firewall),
    ("Port forwards (VIPs)", nat),
    ("Application control", appctrl),
    ("Inspection profiles and certificates", security),
    ("Live traffic", traffic),
    ("Logs", logs),
    ("Routing", network),
    ("DNS and DHCP", dns_dhcp),
    ("Kubernetes (optional, `K8S_KUBECONFIG`)", k8s),
    ("Proxmox VE (optional, `PROXMOX_*`)", pve),
    ("Raw API", raw),
]
START, END = "<!-- TOOLS:START -->", "<!-- TOOLS:END -->"


def first_sentence(text: str) -> str:
    # Split at ". " followed by a capital letter so "e.g. foo" stays intact.
    head = re.split(r"(?<=[.!?])\s+(?=[A-Z])", " ".join(text.split()), maxsplit=1)[0]
    return head.replace("|", "\\|")


def all_tools() -> list[dict]:
    return [t for _, mod in AREAS for t in mod.TOOLS]


def render() -> str:
    total = len(all_tools())
    lines = [START, "", f"**{total} tools** in {len(AREAS)} areas. Expand an area for one line per tool; "
             "your MCP client shows each tool's full description and input schema.", ""]
    for title, mod in AREAS:
        lines += [f"<details><summary><b>{title}</b> · {len(mod.TOOLS)}</summary>", "",
                  "| Tool | What it does |", "|---|---|"]
        lines += [f"| `{t['name']}` | {first_sentence(t['description'])} |" for t in mod.TOOLS]
        lines += ["", "</details>", ""]
    lines.append(END)
    return "\n".join(lines)


def main() -> int:
    readme = ROOT / "README.md"
    text = readme.read_text()
    if START not in text or END not in text:
        print("README.md has no TOOLS markers", file=sys.stderr)
        return 1
    new = text[: text.index(START)] + render() + text[text.index(END) + len(END):]
    if "--check" in sys.argv:
        if new != text:
            print("README tool catalog is out of date: run python3 scripts/gen_tool_catalog.py", file=sys.stderr)
            return 1
        print("README tool catalog is up to date")
        return 0
    readme.write_text(new)
    print(f"updated README.md: {len(all_tools())} tools")
    return 0


if __name__ == "__main__":
    sys.exit(main())
