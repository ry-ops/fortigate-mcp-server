"""Application control: find application signatures and manage app-control profile rules.

Works on the evaluation license with the signatures bundled in FortiOS (no FortiGuard updates).
A profile only acts on traffic through policies that use it (application_list on the policy).
"""

from __future__ import annotations

from typing import Any

from ..client import FortiGateClient
from ._common import INT, STR, STR_LIST, mkey, one, results, schema, vdom_param, write_result
from .traffic import app_names

APP_LIST = "/api/v2/cmdb/application/list"
APP_NAME = "/api/v2/cmdb/application/name"
ACTIONS = ("block", "pass", "monitor", "reset")

TOOLS = [
    {
        "name": "search_applications",
        "description": (
            "Search application-control signatures by name (contains, case-insensitive) and/or "
            "category, e.g. query=YouTube or category=P2P. Returns id, name, category and risk."
        ),
        "inputSchema": schema(
            {
                "query": STR("Text the application name contains"),
                "category": STR("Category name or id, e.g. P2P, Proxy, Video/Audio"),
                "limit": INT("Maximum results (default 25)"),
            }
        ),
    },
    {
        "name": "list_app_categories",
        "description": "Application-control categories (id and name), e.g. P2P, Proxy, Game, Video/Audio.",
        "inputSchema": schema({}),
    },
    {
        "name": "list_app_control_profiles",
        "description": "App-control profiles with their rules, showing application and category names instead of ids.",
        "inputSchema": schema({"name": STR("Only this profile")}),
    },
    {
        "name": "add_app_control_rule",
        "description": (
            "Add a rule to an app-control profile matching applications and/or categories by name "
            "(or id). Rules are checked top-down and the built-in profiles start with a catch-all "
            "pass rule, so new rules are inserted at the top by default (position=bottom to append). "
            "Only affects policies whose application_list is this profile."
        ),
        "inputSchema": schema(
            {
                "profile": STR("Profile name, e.g. default"),
                "applications": STR_LIST("Application names or ids, e.g. [YouTube, BitTorrent]"),
                "categories": STR_LIST("Category names or ids, e.g. [P2P, Proxy]"),
                "action": STR("block, pass, monitor (default) or reset"),
                "log": {"type": "boolean", "description": "Log matches (default true)"},
                "position": STR("top (default) or bottom"),
            },
            ["profile"],
        ),
    },
    {
        "name": "delete_app_control_rule",
        "description": "Remove a rule from an app-control profile by its id (see list_app_control_profiles).",
        "inputSchema": schema({"profile": STR("Profile name"), "id": INT("Rule id")}, ["profile", "id"]),
    },
]


async def _categories(client: FortiGateClient, v: dict[str, Any]) -> dict[int, str]:
    cats = results(await client.get("/api/v2/monitor/utm/application-categories", v))
    return {c["id"]: c["name"] for c in cats} if isinstance(cats, list) else {}


def _category_id(value: str, cats: dict[int, str]) -> int:
    if str(value).isdigit():
        return int(value)
    for cid, cname in cats.items():
        if cname.lower() == str(value).lower():
            return cid
    raise ValueError(f"Unknown category {value!r}; known: {', '.join(sorted(cats.values()))}")


async def _app_id(client: FortiGateClient, value: str, v: dict[str, Any]) -> int:
    if str(value).isdigit():
        return int(value)
    found = results(await client.get(APP_NAME, {**v, "filter": f"name=={value}", "format": "id|name"}))
    if isinstance(found, list) and found:
        return int(found[0]["id"])
    similar = results(await client.get(APP_NAME, {**v, "filter": f"name=@{value}", "format": "name"}))
    hint = [s["name"] for s in similar[:8]] if isinstance(similar, list) else []
    raise ValueError(f"No application named {value!r}" + (f"; did you mean one of {hint}?" if hint else ""))


async def handle(name: str, args: dict[str, Any], client: FortiGateClient) -> Any:
    v = vdom_param(args)

    if name == "search_applications":
        cats = await _categories(client, v)
        filters = []
        if args.get("query"):
            filters.append(f"name=@{args['query']}")
        if args.get("category"):
            filters.append(f"category=={_category_id(args['category'], cats)}")
        if not filters:
            raise ValueError("Give query and/or category")
        params = {**v, "filter": filters, "format": "id|name|category|risk|technology|vendor"}
        found = results(await client.get(APP_NAME, params))
        if not isinstance(found, list):
            return found
        limit = args.get("limit", 25)
        return {
            "matches": len(found),
            "results": [
                {**{k: a.get(k) for k in ("id", "name", "risk", "technology", "vendor")},
                 "category": cats.get(a.get("category"), a.get("category"))}
                for a in found[:limit]
            ],
        }

    elif name == "list_app_categories":
        cats = await _categories(client, v)
        return [{"id": i, "name": n} for i, n in sorted(cats.items())]

    elif name == "list_app_control_profiles":
        cats = await _categories(client, v)
        path = f"{APP_LIST}/{mkey(args['name'])}" if args.get("name") else APP_LIST
        profiles = results(await client.get(path, v))
        profiles = profiles if isinstance(profiles, list) else [profiles]
        app_ids = {a["id"] for p in profiles for e in p.get("entries") or [] for a in e.get("application") or []}
        apps = await app_names(client, app_ids, v) if app_ids else {}
        out = []
        for p in profiles:
            out.append(
                {
                    "name": p.get("name"),
                    "comment": p.get("comment"),
                    "other_applications": p.get("other-application-action"),
                    "unknown_applications": p.get("unknown-application-action"),
                    "rules": [
                        {
                            "id": e.get("id"),
                            "action": e.get("action"),
                            "applications": [apps.get(a["id"], a["id"]) for a in e.get("application") or []],
                            "categories": [cats.get(c["id"], c["id"]) for c in e.get("category") or []],
                            "log": e.get("log"),
                        }
                        for e in p.get("entries") or []
                    ],
                }
            )
        return out

    elif name == "add_app_control_rule":
        action = args.get("action", "monitor")
        if action not in ACTIONS:
            raise ValueError(f"action must be one of {', '.join(ACTIONS)}")
        if not args.get("applications") and not args.get("categories"):
            raise ValueError("Give applications and/or categories")
        cats = await _categories(client, v)
        cat_ids = [_category_id(c, cats) for c in args.get("categories") or []]
        app_ids = [await _app_id(client, a, v) for a in args.get("applications") or []]
        profile = one(await client.get(f"{APP_LIST}/{mkey(args['profile'])}", v))
        existing = (profile.get("entries") or []) if isinstance(profile, dict) else []
        rule_id = max((e.get("id", 0) for e in existing), default=0) + 1
        entry = {
            "id": rule_id,
            "action": action,
            "log": "enable" if args.get("log", True) else "disable",
            "application": [{"id": i} for i in app_ids],
            "category": [{"id": i} for i in cat_ids],
        }
        base = f"{APP_LIST}/{mkey(args['profile'])}/entries"
        out = write_result(await client.post(base, entry, v))
        out["rule_id"] = rule_id
        position = args.get("position", "top")
        if position not in ("top", "bottom"):
            raise ValueError("position must be top or bottom")
        if position == "top" and existing:
            # Ordered cmdb tables support action=move; put the rule before the current first rule.
            await client.put(f"{base}/{rule_id}", None, {**v, "action": "move", "before": existing[0]["id"]})
            out["position"] = "top"
        elif position == "bottom" and any(not e.get("application") and not e.get("category") for e in existing):
            out["warning"] = "An earlier rule matches all applications, so this rule will never be reached."
        return out

    elif name == "delete_app_control_rule":
        return write_result(await client.delete(f"{APP_LIST}/{mkey(args['profile'])}/entries/{args['id']}", v))

    raise ValueError(f"Unknown tool: {name}")
