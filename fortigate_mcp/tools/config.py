"""Schema-driven access to every FortiOS setting and monitor endpoint.

FortiOS describes its own API: /api/v2/cmdb/?action=schema lists every configuration endpoint
with each field's type, allowed values, range and default, and /api/v2/monitor/?action=schema
lists every monitor endpoint with its HTTP method and parameters. These tools read that schema
from the FortiGate itself, so they match its firmware, and use it to find endpoints, describe
them, and validate writes before anything reaches the device.
"""

from __future__ import annotations

import difflib
from typing import Any

from ..client import FortiGateClient
from ._common import (
    BOOL,
    INT,
    LIST_PROPS,
    OBJ,
    STR,
    list_params,
    mkey,
    results,
    schema,
    vdom_param,
    write_result,
)

CMDB, MONITOR = "/api/v2/cmdb", "/api/v2/monitor"
SECRET = "<set>"

TOOLS = [
    {
        "name": "search_api",
        "description": (
            "Find FortiOS API endpoints by keyword, from the FortiGate's own schema: configuration "
            "(cmdb, e.g. 'bgp' -> router/bgp) and live state (monitor, e.g. 'ha peer' -> "
            "system/ha-peer). Use it to reach any setting no dedicated tool covers, then "
            "describe_config, get_config, set_config or get_monitor."
        ),
        "inputSchema": schema(
            {
                "query": STR("Keywords, e.g. 'ospf area', 'syslog', 'ipsec phase1'"),
                "kind": STR("cmdb, monitor or both (default both)"),
                "limit": INT("Maximum results (default 20)"),
            },
            ["query"],
        ),
    },
    {
        "name": "describe_config",
        "description": (
            "Describe a configuration endpoint from the FortiGate's schema: whether it is a table "
            "(many entries, keyed by mkey) or a single settings object, and each field's type, "
            "allowed values, range and default. Pass field for one field in full, including the "
            "sub-fields of a nested table."
        ),
        "inputSchema": schema(
            {"endpoint": STR("e.g. router/bgp, log.syslogd/setting, firewall/local-in-policy"),
             "field": STR("One field to describe in full (optional)")},
            ["endpoint"],
        ),
    },
    {
        "name": "get_config",
        "description": (
            "Read any configuration endpoint: a whole settings object, every entry of a table, or one "
            "entry by mkey. Password and key fields are shown as '<set>', never their values."
        ),
        "inputSchema": schema(
            {"endpoint": STR("e.g. system/global, router/static, user/local"),
             "mkey": STR("Entry key for a table endpoint (optional)"), **LIST_PROPS},
            ["endpoint"],
        ),
    },
    {
        "name": "set_config",
        "description": (
            "Change any configuration endpoint, validated against the FortiGate's schema first: "
            "field names, option values, integer ranges, string lengths, and table vs single-object "
            "rules. action is update (default), create or delete. With dry_run (the default) nothing "
            "is sent; the result shows the request and each field's current and new value. Fields "
            "that reference other objects take a list of names, e.g. srcaddr: ['LAB-NET']."
        ),
        "inputSchema": schema(
            {
                "endpoint": STR("e.g. log/setting, firewall/local-in-policy"),
                "mkey": STR("Entry key; required to update or delete a table entry"),
                "fields": OBJ("Field values, using the schema's hyphenated names"),
                "action": STR("update, create or delete (default update)"),
                "dry_run": BOOL("Only validate and show the change (default true)"),
            },
            ["endpoint"],
        ),
    },
    {
        "name": "get_monitor",
        "description": (
            "Read any monitor (live state) endpoint, e.g. system/ha-peer, router/ipv4, "
            "vpn/ipsec, user/firewall. Only endpoints FortiOS serves with GET are allowed: monitor "
            "POST endpoints act on the device (reboots, disconnects, updates), so they stay in the "
            "dedicated tools or fortigate_api."
        ),
        "inputSchema": schema(
            {"endpoint": STR("e.g. system/ha-peer or system/available-certificates"),
             "params": OBJ("Query parameters the endpoint documents (see search_api)")},
            ["endpoint"],
        ),
    },
]


def _norm(endpoint: str) -> str:
    e = endpoint.strip().strip("/")
    for prefix in ("api/v2/cmdb/", "api/v2/monitor/", "cmdb/", "monitor/"):
        if e.startswith(prefix):
            e = e[len(prefix):]
    return e


async def _cmdb_index(client: FortiGateClient, v: dict[str, Any]) -> dict[str, dict[str, Any]]:
    cached = getattr(client, "_cmdb_index", None)
    if cached is None:
        resp = results(await client.get(f"{CMDB}/", {**v, "action": "schema"}))
        cached = {
            f"{r['path']}/{r['name']}": {
                "category": r["schema"].get("category"),
                "mkey": r["schema"].get("mkey"),
                "help": r["schema"].get("help", ""),
            }
            for r in resp if isinstance(r, dict) and "schema" in r
        }
        client._cmdb_index = cached  # type: ignore[attr-defined]
    return cached


async def _monitor_index(client: FortiGateClient, v: dict[str, Any]) -> dict[str, dict[str, Any]]:
    cached = getattr(client, "_monitor_index", None)
    if cached is None:
        resp = await client.get(f"{MONITOR}/", {**v, "action": "schema"})
        cached = {}
        for d in (resp.get("directory") if isinstance(resp, dict) else None) or []:
            action = d.get("action", "select")
            ep = f"{d['path']}/{d['name']}" + ("" if action == "select" else f"/{action}")
            req = d.get("request") or {}
            cached[ep] = {
                "method": req.get("http_method", "GET"),
                "help": d.get("summary", ""),
                "supported": d.get("supported", True),
                "params": [p.get("name") for p in req.get("parameters") or []],
            }
        client._monitor_index = cached  # type: ignore[attr-defined]
    return cached


async def _schema(client: FortiGateClient, v: dict[str, Any], endpoint: str) -> dict[str, Any]:
    cache = client.__dict__.setdefault("_endpoint_schemas", {})
    if endpoint not in cache:
        index = await _cmdb_index(client, v)
        if endpoint not in index:
            close = difflib.get_close_matches(endpoint, index, n=5, cutoff=0.6)
            hint = f" Did you mean: {', '.join(close)}?" if close else " Try search_api."
            raise ValueError(f"Unknown configuration endpoint '{endpoint}'.{hint}")
        cache[endpoint] = results(await client.get(f"{CMDB}/{endpoint}", {**v, "action": "schema"}))
    return cache[endpoint]


def _is_secret(f: dict[str, Any]) -> bool:
    t = str(f.get("type") or "")
    return t.startswith("password") or t == "key"


def _field_summary(f: dict[str, Any], depth: int = 0) -> dict[str, Any]:
    if f.get("category") == "table":
        out: dict[str, Any] = {"type": "table", "help": f.get("help", ""), "key": f.get("mkey")}
        children = f.get("children") or {}
        if depth == 0:
            out["fields"] = sorted(children)
        else:
            out["fields"] = {k: _field_summary(c, depth - 1) for k, c in children.items()}
        return out
    out = {"type": f.get("type"), "help": f.get("help", "")}
    if f.get("options"):
        out["options"] = [o.get("name") for o in f["options"]]
    for src, dst in (("default", "default"), ("min-value", "min"), ("max-value", "max"), ("size", "max_length")):
        if f.get(src) not in (None, ""):
            out[dst] = f[src]
    if f.get("multiple_values"):
        out["multiple"] = True
    if f.get("required"):
        out["required"] = True
    if _is_secret(f):
        out["secret"] = True
    return out


def _mask(value: Any, sch: dict[str, Any]) -> Any:
    """Replace secret field values with '<set>' throughout a config object or list."""
    children = sch.get("children") or {}
    if isinstance(value, list):
        return [_mask(v, sch) for v in value]
    if not isinstance(value, dict):
        return value
    out = {}
    for k, val in value.items():
        f = children.get(k) or {}
        if _is_secret(f):
            out[k] = SECRET if val not in (None, "") else val
        elif f.get("category") == "table":
            out[k] = _mask(val, f)
        else:
            out[k] = val
    return out


def _validate(sch: dict[str, Any], fields: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Check fields against the schema; return the request body and a list of errors."""
    children = sch.get("children") or {}
    body: dict[str, Any] = {}
    errors: list[str] = []
    for name, value in fields.items():
        f = children.get(name)
        if f is None:
            close = difflib.get_close_matches(name, children, n=3)
            errors.append(f"unknown field '{name}'" + (f" (did you mean {', '.join(close)}?)" if close else ""))
            continue
        if f.get("category") == "table":
            key = f.get("mkey") or "name"
            items = value if isinstance(value, list) else [value]
            body[name] = [i if isinstance(i, dict) else {key: i} for i in items]
            continue
        t = f.get("type")
        if t == "option" and f.get("options"):
            allowed = [o.get("name") for o in f["options"]]
            vals = str(value).split() if f.get("multiple_values") else [str(value)]
            bad = [x for x in vals if x not in allowed]
            if bad:
                errors.append(f"{name}: {', '.join(bad)} not one of {', '.join(allowed)}")
        elif t == "integer":
            try:
                value = int(value)
            except (TypeError, ValueError):
                errors.append(f"{name}: expected an integer, got {value!r}")
                continue
            lo, hi = f.get("min-value"), f.get("max-value")
            if (lo is not None and value < lo) or (hi is not None and value > hi):
                errors.append(f"{name}: {value} outside {lo}-{hi}")
        elif t in ("string", "var-string") and f.get("size") and len(str(value)) > f["size"]:
            errors.append(f"{name}: longer than {f['size']} characters")
        body[name] = value
    return body, errors


async def set_config(client: FortiGateClient, args: dict[str, Any]) -> dict[str, Any]:
    v = vdom_param(args)
    endpoint = _norm(args["endpoint"])
    action = (args.get("action") or "update").lower()
    dry_run = args.get("dry_run", True) is not False
    sch = await _schema(client, v, endpoint)
    is_table = sch.get("category") == "table"
    key_name = sch.get("mkey")
    key = args.get("mkey")
    fields = dict(args.get("fields") or {})

    if action not in ("update", "create", "delete"):
        raise ValueError("action must be update, create or delete")
    if not is_table and action != "update":
        raise ValueError(f"{endpoint} is a single settings object: only update applies")
    if is_table and action in ("update", "delete") and key in (None, ""):
        raise ValueError(f"{endpoint} is a table keyed by '{key_name}': pass mkey to {action} an entry")
    if action == "create" and key not in (None, "") and key_name:
        fields.setdefault(key_name, key)
    if action != "delete" and not fields:
        raise ValueError("Pass fields to set")

    body, errors = _validate(sch, fields) if action != "delete" else ({}, [])
    if errors:
        return {"valid": False, "errors": errors, "hint": f"describe_config endpoint={endpoint} lists the fields"}

    base = f"{CMDB}/{endpoint}"
    path = f"{base}/{mkey(key)}" if is_table and action != "create" else base
    method = {"update": "PUT", "create": "POST", "delete": "DELETE"}[action]

    current: Any = None
    if action in ("update", "delete"):
        cur = results(await client.get(path, v))
        current = cur[0] if isinstance(cur, list) and cur else cur
    changes: dict[str, Any] = {}
    if action == "delete":
        changes = {"entry": _mask(current, sch)}
    else:
        masked_cur = _mask(current or {}, sch)
        masked_new = _mask(body, sch)
        children = sch.get("children") or {}
        for k in body:
            before = masked_cur.get(k) if isinstance(masked_cur, dict) else None
            # A stored secret is a hash, so a new one can't be compared with it: always a change.
            if before != masked_new[k] or action == "create" or _is_secret(children.get(k) or {}):
                changes[k] = {"current": before, "new": masked_new[k]}

    out: dict[str, Any] = {"request": f"{method} {path}", "changes": changes}
    if action == "update" and not changes:
        return {**out, "note": "Nothing to change: every field already has that value"}
    if dry_run:
        return {"dry_run": True, **out, "note": "Validated against the schema. Set dry_run=false to apply."}
    if method == "PUT":
        resp = await client.put(path, body, v)
    elif method == "POST":
        resp = await client.post(path, body, v)
    else:
        resp = await client.delete(path, v)
    return {**out, "result": write_result(resp)}


def _score(query: list[str], endpoint: str, text: str) -> int:
    ep, text = endpoint.lower(), text.lower()
    return sum((3 if w in ep else 0) + (1 if w in text else 0) for w in query) if all(
        w in ep or w in text for w in query) else 0


async def handle(name: str, args: dict[str, Any], client: FortiGateClient) -> Any:
    v = vdom_param(args)

    if name == "search_api":
        words = [w for w in args["query"].lower().replace("/", " ").split() if w]
        kind = (args.get("kind") or "both").lower()
        hits: list[tuple[int, dict[str, Any]]] = []
        if kind in ("cmdb", "both"):
            for ep, meta in (await _cmdb_index(client, v)).items():
                s = _score(words, ep, meta["help"])
                if s:
                    hits.append((s, {"kind": "cmdb", "endpoint": ep, "type": meta["category"],
                                     "key": meta["mkey"], "help": meta["help"]}))
        if kind in ("monitor", "both"):
            for ep, meta in (await _monitor_index(client, v)).items():
                s = _score(words, ep, meta["help"])
                if s and meta["supported"]:
                    hits.append((s, {"kind": "monitor", "endpoint": ep, "method": meta["method"],
                                     "help": meta["help"], **({"params": meta["params"]} if meta["params"] else {})}))
        hits.sort(key=lambda h: (-h[0], h[1]["endpoint"]))
        limit = args.get("limit") or 20
        return {"matches": len(hits), "results": [h for _, h in hits[:limit]]}

    elif name == "describe_config":
        endpoint = _norm(args["endpoint"])
        sch = await _schema(client, v, endpoint)
        children = sch.get("children") or {}
        if args.get("field"):
            f = children.get(args["field"])
            if f is None:
                close = difflib.get_close_matches(args["field"], children, n=3)
                raise ValueError(f"No field '{args['field']}' in {endpoint}" + (f"; did you mean {', '.join(close)}?" if close else ""))
            return {"endpoint": endpoint, "field": args["field"], **_field_summary(f, depth=2)}
        return {
            "endpoint": endpoint,
            "type": "table" if sch.get("category") == "table" else "settings",
            "key": sch.get("mkey"),
            "help": sch.get("help", ""),
            "fields": {k: _field_summary(f) for k, f in children.items()},
        }

    elif name == "get_config":
        endpoint = _norm(args["endpoint"])
        sch = await _schema(client, v, endpoint)
        path = f"{CMDB}/{endpoint}" + (f"/{mkey(args['mkey'])}" if args.get("mkey") not in (None, "") else "")
        return _mask(results(await client.get(path, list_params(args))), sch)

    elif name == "set_config":
        return await set_config(client, args)

    elif name == "get_monitor":
        endpoint = _norm(args["endpoint"])
        index = await _monitor_index(client, v)
        meta = index.get(endpoint)
        if meta is None:
            close = difflib.get_close_matches(endpoint, index, n=5, cutoff=0.6)
            raise ValueError(f"Unknown monitor endpoint '{endpoint}'." + (f" Did you mean: {', '.join(close)}?" if close else " Try search_api."))
        if meta["method"] != "GET":
            raise ValueError(f"monitor/{endpoint} is a {meta['method']} endpoint that acts on the FortiGate; "
                             "use a dedicated tool or fortigate_api deliberately")
        params = dict(args.get("params") or {})
        unknown = [p for p in params if meta["params"] and p not in meta["params"]]
        if unknown:
            raise ValueError(f"monitor/{endpoint} takes {', '.join(meta['params'])}; not {', '.join(unknown)}")
        return results(await client.get(f"{MONITOR}/{endpoint}", {**v, **params}))

    raise ValueError(f"Unknown tool: {name}")
