#!/usr/bin/env python3
"""Generate docs/demo.svg: an animated Claude Code session using fortigate-mcp-server.

Each scene types a prompt, then reveals the tool call, its result and Claude's reply. The
outputs mirror a real run against a FortiGate-VM (permanent trial) fronting a 3-node k3s lab.
Run: python3 scripts/build_demo_svg.py
"""

from __future__ import annotations

from pathlib import Path
from xml.sax.saxutils import escape

W, H = 900, 340
SCENE = 10.0  # seconds per scene
TOP, LINE = 74, 23

# (kind, text, reveal_time_in_scene). kinds: prompt, call, out, ok, err, dim, say
SCENES = [
    [
        ("prompt", "Who is using the most bandwidth right now?", 0.4),
        ("call", "get_top_traffic(report_by=\"destination\", resolve_vms=true)", 2.4),
        ("out", "speed.cloudflare.com:443   13.8 MB   HTTPS.BROWSER", 3.4),
        ("dim", "from 192.168.150.12 = 112 k3s-worker2 (qemu on pve01)", 3.8),
        ("say", "One heavy flow: VM 112 (k3s-worker2) is downloading from", 5.4),
        ("say", "speed.cloudflare.com, so a speed test. Nothing else is busy.", 5.7),
    ],
    [
        ("prompt", "Give the whoami app a name on the lab network.", 0.4),
        ("call", "k8s_sync_ingress_dns(zone=\"lab\", dry_run=false)", 2.4),
        ("ok", "+ whoami.lab -> 192.168.150.10", 3.4),
        ("ok", "+ whoami.lab -> 192.168.150.11", 3.7),
        ("ok", "+ whoami.lab -> 192.168.150.12", 4.0),
        ("dim", "skipped: none   ·   running it again changes nothing", 4.4),
        ("say", "whoami.lab now resolves behind the FortiGate, one A record per", 5.6),
        ("say", "Traefik IP, since FortiOS can't hold a *.lab wildcard.", 5.9),
    ],
    [
        ("prompt", "Publish Traefik on the firewall's WAN address, port 8443.", 0.4),
        ("call", "create_port_forward(extport=8443, mappedport=443, attach_to_policy=3)", 2.4),
        ("err", "Policy 3 has ordinary destinations ['K3S-NODES'], and FortiOS cannot", 3.4),
        ("err", "mix them with VIPs. (Nothing was created.)", 3.6),
        ("call", "get_license_limits()", 4.6),
        ("out", "policies 3/3 used, 0 free   ·   interfaces 2/3   ·   routes 0/3", 5.4),
        ("say", "No policy slot is free on the trial license. I can turn policy 3", 6.4),
        ("say", "into a VIP-only policy (replace_destinations=true). Go ahead?", 6.7),
    ],
]

COLORS = {"prompt": "#e6edf3", "call": "#e6edf3", "out": "#c9d1d9", "ok": "#3fb950", "err": "#f85149",
          "dim": "#8b949e", "say": "#e6edf3"}


def kt(*times: float) -> str:
    """SMIL keyTimes: fractions of the loop, which must start at 0 and end at 1."""
    total = SCENE * len(SCENES)
    return ";".join(f"{min(max(t / total, 0), 1):.4f}" for t in times)


def main() -> None:
    total = SCENE * len(SCENES)
    defs, body = [], []
    for si, scene in enumerate(SCENES):
        start = si * SCENE
        group = ['  <g opacity="0">',
                 f'    <animate attributeName="opacity" values="0;0;1;1;0;0" keyTimes="{kt(0, start, start + .2, start + SCENE - .4, start + SCENE - .1, total)}" dur="{total:g}s" repeatCount="indefinite"/>']
        y = TOP
        for li, (kind, text, t) in enumerate(scene):
            at = start + t
            if kind == "prompt":
                cid = f"c{si}{li}"
                width = 24 + len(text) * 8.7
                defs.append(f'    <clipPath id="{cid}"><rect x="40" y="{y - 16}" height="24" width="0">'
                            f'<animate attributeName="width" values="0;0;{width:.0f};{width:.0f}" '
                            f'keyTimes="{kt(0, at, at + min(1.6, len(text) * .035), total)}" dur="{total:g}s" repeatCount="indefinite"/></rect></clipPath>')
                group.append(f'    <g clip-path="url(#{cid})"><text x="40" y="{y}" class="m" fill="#2dd4bf">&gt;</text>'
                             f'<text x="58" y="{y}" class="m" fill="{COLORS[kind]}">{escape(text)}</text></g>')
                y += LINE + 10
                continue
            appear = (f'<animate attributeName="opacity" values="0;0;1;1" keyTimes="{kt(0, at, at + .25, total)}" '
                      f'dur="{total:g}s" repeatCount="indefinite"/>')
            if kind == "call":
                if y > TOP + LINE + 10:
                    y += 6
                group.append(f'    <g opacity="0">{appear}<circle cx="46" cy="{y - 4}" r="4.5" fill="#2dd4bf"/>'
                             f'<text x="58" y="{y}" class="m"><tspan fill="#8b949e">fortigate · </tspan>'
                             f'<tspan fill="{COLORS[kind]}" font-weight="600">{escape(text)}</tspan></text></g>')
                y += LINE
            elif kind == "say":
                if scene[li - 1][0] != "say":
                    y += 10
                    group.append(f'    <g opacity="0">{appear}<circle cx="46" cy="{y - 4}" r="4.5" fill="#e6edf3"/></g>')
                group.append(f'    <g opacity="0">{appear}<text x="58" y="{y}" class="s" fill="{COLORS[kind]}">{escape(text)}</text></g>')
                y += LINE
            else:
                # The tree glyph and the content sit at fixed x so every result row lines up.
                first = scene[li - 1][0] == "call"
                mark = "✗ " if kind == "err" and first else ("  " if kind == "err" else "")
                glyph = f'<text x="66" y="{y}" class="m" fill="#484f58">⎿</text>' if first else ""
                group.append(f'    <g opacity="0">{appear}{glyph}<text x="86" y="{y}" class="m" '
                             f'fill="{COLORS[kind]}">{mark}{escape(text)}</text></g>')
                y += LINE
        assert y < H - 40, f"scene {si} overflows ({y})"
        group.append("  </g>")
        body.extend(group)

    # progress dots for the three scenes
    dots = []
    for si in range(len(SCENES)):
        start = si * SCENE
        cx = W / 2 - 16 + si * 16
        dots.append(f'  <circle cx="{cx:g}" cy="{H - 22}" r="4" fill="#30363d"/>')
        dots.append(f'  <circle cx="{cx:g}" cy="{H - 22}" r="4" fill="#2dd4bf" opacity="0"><animate attributeName="opacity" '
                    f'values="0;0;1;1;0;0" keyTimes="{kt(0, start, start + .2, start + SCENE - .4, start + SCENE - .1, total)}" '
                    f'dur="{total:g}s" repeatCount="indefinite"/></circle>')

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img" aria-labelledby="t d" xml:space="preserve">
  <title id="t">fortigate-mcp-server in a Claude Code session</title>
  <desc id="d">Three looping scenes: finding the top bandwidth users with their Proxmox VM names, syncing a Kubernetes Ingress hostname into FortiGate DNS, and a port forward refused up front because FortiOS cannot mix VIPs with addresses while the free license has no policy slot left.</desc>
  <defs>
{chr(10).join(defs)}
    <style>
      .m{{white-space:pre;font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;font-size:14px}}
      .s{{font-family:"Segoe UI",-apple-system,BlinkMacSystemFont,Helvetica,Arial,sans-serif;font-size:15px}}
      .blink{{animation:blink 1s steps(1) infinite}}@keyframes blink{{50%{{opacity:0}}}}
      @media (prefers-reduced-motion:reduce){{*{{animation:none!important}}}}
    </style>
  </defs>
  <rect x="1" y="1" width="{W - 2}" height="{H - 2}" rx="14" fill="#0d1117" stroke="#30363d"/>
  <path d="M1 15a14 14 0 0 1 14-14h{W - 30}a14 14 0 0 1 14 14v23H1z" fill="#161b22"/>
  <line x1="1" y1="38" x2="{W - 1}" y2="38" stroke="#30363d"/>
  <circle cx="24" cy="20" r="6" fill="#f85149"/><circle cx="44" cy="20" r="6" fill="#d29922"/><circle cx="64" cy="20" r="6" fill="#3fb950"/>
  <text x="{W / 2:g}" y="25" text-anchor="middle" class="m" fill="#8b949e" font-size="12">claude  ·  mcp: fortigate (74 tools, read-only)</text>
{chr(10).join(body)}
{chr(10).join(dots)}
  <text x="{W - 24}" y="{H - 18}" text-anchor="end" class="m" fill="#484f58" font-size="11">replays a real lab session</text>
</svg>
'''
    out = Path(__file__).resolve().parent.parent / "docs" / "demo.svg"
    out.write_text(svg)
    print(f"wrote {out} ({len(svg)} bytes)")


if __name__ == "__main__":
    main()
