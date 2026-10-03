"""The README and its visuals stay in step with the code."""

import importlib.util
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from fortigate_mcp import __version__

ROOT = Path(__file__).resolve().parent.parent
README = (ROOT / "README.md").read_text()
SVGS = sorted((ROOT / "docs").glob("*.svg"))

spec = importlib.util.spec_from_file_location("gen_tool_catalog", ROOT / "scripts" / "gen_tool_catalog.py")
catalog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(catalog)
TOOL_COUNT = len(catalog.all_tools())


def test_tool_catalog_matches_code():
    start, end = README.index(catalog.START), README.index(catalog.END) + len(catalog.END)
    assert README[start:end] == catalog.render(), "run python3 scripts/gen_tool_catalog.py"


def test_tool_names_are_unique():
    names = [t["name"] for t in catalog.all_tools()]
    assert len(names) == len(set(names))


@pytest.mark.parametrize("name", ["banner.svg", "architecture.svg", "demo.svg"])
def test_visuals_show_current_tool_count(name):
    assert f"{TOOL_COUNT} " in (ROOT / "docs" / name).read_text()


@pytest.mark.parametrize("name", ["banner.svg", "architecture.svg"])
def test_visuals_show_current_version(name):
    assert f"v{__version__}" in (ROOT / "docs" / name).read_text()


def test_readme_pins_current_version_and_count():
    assert f"@v{__version__}" in README
    assert f"{TOOL_COUNT} MCP tools" in README


def test_readme_images_exist():
    for src in re.findall(r'src="(docs/[^"]+)"', README):
        assert (ROOT / src).exists(), src


@pytest.mark.parametrize("svg", SVGS, ids=lambda p: p.name)
def test_svg_animations_are_well_formed(svg):
    tree = ET.parse(svg)  # also proves the file is valid XML
    for el in tree.iter():
        key_times = el.get("keyTimes")
        if not key_times:
            continue
        times = [float(t) for t in key_times.split(";")]
        assert times[0] == 0 and times[-1] == 1, f"{svg.name}: keyTimes must run from 0 to 1"
        assert times == sorted(times), f"{svg.name}: keyTimes must not decrease"
        values = el.get("values") or el.get("keyPoints")
        assert values and len(values.split(";")) == len(times), f"{svg.name}: values/keyTimes length mismatch"
    text = svg.read_text()
    assert "<script" not in text and "foreignObject" not in text, "GitHub strips scripts from SVGs"
    assert "prefers-reduced-motion" in text or "animate" not in text
