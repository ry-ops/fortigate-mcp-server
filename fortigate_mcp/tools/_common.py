"""Helpers shared by the tool modules: schema shortcuts and FortiOS body conventions."""

from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import quote

STR = lambda desc: {"type": "string", "description": desc}  # noqa: E731
INT = lambda desc: {"type": "integer", "description": desc}  # noqa: E731
BOOL = lambda desc: {"type": "boolean", "description": desc}  # noqa: E731
STR_LIST = lambda desc: {"type": "array", "items": {"type": "string"}, "description": desc}  # noqa: E731
OBJ = lambda desc: {"type": "object", "description": desc, "additionalProperties": True}  # noqa: E731

VDOM = STR("VDOM (default: FORTIGATE_VDOM, usually root)")
FILTER = STR("FortiOS filter expression, e.g. name=@k3s (contains) or action==accept")
EXTRA = OBJ("Extra FortiOS attributes merged into the request body as-is (hyphenated keys)")


def schema(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    s: dict[str, Any] = {"type": "object", "properties": {**properties, "vdom": VDOM}}
    if required:
        s["required"] = required
    return s


def mkey(value: Any) -> str:
    """Quote an object name for use in a cmdb path (names may contain spaces or slashes)."""
    return quote(str(value), safe="")


def names(values: list[str] | str | None) -> list[dict[str, str]] | None:
    """FortiOS references other objects as [{"name": ...}]."""
    if values is None:
        return None
    if isinstance(values, str):
        values = [values]
    return [{"name": v} for v in values]


def subnet(cidr_or_pair: str) -> str:
    """Accept 10.0.0.0/24 or '10.0.0.0 255.255.255.0' and return FortiOS's 'ip mask' form."""
    if "/" in cidr_or_pair:
        net = ipaddress.ip_interface(cidr_or_pair)
        return f"{net.ip} {net.network.netmask}"
    return cidr_or_pair


def body(args: dict[str, Any], mapping: dict[str, str], list_fields: tuple[str, ...] = ()) -> dict[str, Any]:
    """Build a FortiOS body from tool args.

    ``mapping`` maps tool argument names (snake_case) to FortiOS attribute names
    (hyphenated). Fields in ``list_fields`` become name references. ``extra``
    is merged last so callers can set any attribute the tool does not model.
    """
    out: dict[str, Any] = {}
    for arg, attr in mapping.items():
        if arg in args and args[arg] is not None:
            out[attr] = names(args[arg]) if arg in list_fields else args[arg]
    out.update(args.get("extra") or {})
    return out


def compact(data: Any) -> Any:
    """Drop FortiOS's q_* bookkeeping keys so results stay readable."""
    if isinstance(data, dict):
        return {k: compact(v) for k, v in data.items() if not k.startswith("q_")}
    if isinstance(data, list):
        return [compact(v) for v in data]
    return data


def list_params(args: dict[str, Any]) -> dict[str, Any]:
    params: dict[str, Any] = {}
    if args.get("filter"):
        params["filter"] = args["filter"]
    if args.get("format"):
        params["format"] = args["format"]
    if args.get("vdom"):
        params["vdom"] = args["vdom"]
    return params


LIST_PROPS = {
    "filter": FILTER,
    "format": STR("Only return these fields, '|'-separated, e.g. policyid|name|action"),
}


def results(resp: Any) -> Any:
    """Return the useful part of a FortiOS GET response."""
    if isinstance(resp, dict) and "results" in resp:
        return compact(resp["results"])
    return compact(resp)


def write_result(resp: Any) -> Any:
    """Summarise a FortiOS write response (status, key of the changed object)."""
    if isinstance(resp, dict):
        return {k: resp[k] for k in ("status", "mkey", "http_status", "revision_changed") if k in resp}
    return resp


def vdom_param(args: dict[str, Any]) -> dict[str, Any]:
    return {"vdom": args.get("vdom")}


def one(resp: Any) -> Any:
    """GET on a single cmdb object still returns a one-item list; unwrap it."""
    res = results(resp)
    if isinstance(res, list) and len(res) == 1:
        return res[0]
    return res
