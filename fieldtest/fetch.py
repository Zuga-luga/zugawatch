"""Registry export fetcher — pull real MCP server manifests into the field-test
format ({"servers": [{"name", "tools": [{name, description, inputSchema}]}]}).

    python fieldtest/fetch.py --source glama    --limit 200 --out fieldtest/servers.glama.json
    python fieldtest/fetch.py --source smithery --limit 200 --out fieldtest/servers.smithery.json

Sources:
  glama     public, no auth. NOTE: Glama's API returns an empty tools[] for most
            servers, so this mostly yields names/descriptions — useful for the
            server-level scan, thin for tool-poisoning. (Verified June 2026.)
  smithery  needs a free API key in $SMITHERY_API_KEY (https://smithery.ai/account/api-keys).
            Its detail endpoint serves real tools[] with inputSchema — this is
            the source for genuine tool-poisoning field data.

Stdlib only (urllib) — no new dependency. Servers are never executed; we only
read published manifest JSON.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

UA = {"User-Agent": "zugawatch-fieldtest/0.5 (+https://github.com/Zuga-luga/zugawatch)"}


def _get(url: str, headers: dict[str, str] | None = None, retries: int = 2):
    req = urllib.request.Request(url, headers={**UA, **(headers or {})})
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return json.loads(r.read().decode("utf-8"))
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as e:
            if attempt == retries:
                raise
            time.sleep(1.0 + attempt)
    return None


def _tool(t: dict) -> dict:
    return {
        "name": t.get("name", ""),
        "description": t.get("description", "") or "",
        "inputSchema": t.get("inputSchema", t.get("input_schema", {})) or {},
    }


# ------------------------------ Glama -------------------------------------

def fetch_glama(limit: int) -> list[dict]:
    base = "https://glama.ai/api/mcp/v1/servers"
    out: list[dict] = []
    seen: set[str] = set()
    cursor = None
    while len(out) < limit:
        url = base + (f"?after={urllib.parse.quote(cursor)}" if cursor else "")
        data = _get(url)
        servers = data.get("servers", [])
        if not servers:
            break
        for s in servers:
            name = s.get("slug") or s.get("name")
            if name in seen:
                continue
            seen.add(name)
            detail = _safe_detail(f"https://glama.ai/api/mcp/v1/servers/{s['id']}")
            tools = [_tool(t) for t in (detail.get("tools") if detail else []) or []]
            out.append({"name": name, "tools": tools})
            if len(out) >= limit:
                break
        page = data.get("pageInfo", {})
        if not page.get("hasNextPage"):
            break
        cursor = page.get("endCursor")
        if not cursor:
            break
    return out


def _safe_detail(url: str):
    try:
        return _get(url)
    except Exception:  # noqa: BLE001 - one bad server shouldn't abort the export
        return None


# ----------------------------- Smithery -----------------------------------

def fetch_smithery(limit: int, query: str = "") -> list[dict]:
    key = os.environ.get("SMITHERY_API_KEY")
    if not key:
        raise SystemExit("Set $SMITHERY_API_KEY (free at https://smithery.ai/account/api-keys).")
    headers = {"Authorization": f"Bearer {key}"}
    out: list[dict] = []
    seen: set[str] = set()
    page = 1
    while len(out) < limit:
        q = urllib.parse.urlencode({"q": query, "page": page, "pageSize": 50})
        data = _get(f"https://registry.smithery.ai/servers?{q}", headers)
        servers = data.get("servers", []) or data.get("data", [])
        if not servers:
            break
        for s in servers:
            qn = s.get("qualifiedName") or s.get("name")
            if qn in seen:
                continue
            seen.add(qn)
            detail = _safe_detail_h(f"https://registry.smithery.ai/servers/{urllib.parse.quote(qn)}", headers)
            tools = [_tool(t) for t in (detail.get("tools") if detail else []) or []]
            out.append({"name": qn, "tools": tools})
            if len(out) >= limit:
                break
        if page >= (data.get("pagination", {}).get("totalPages", page)):
            break
        page += 1
    return out


def _safe_detail_h(url: str, headers: dict[str, str]):
    try:
        return _get(url, headers)
    except Exception:  # noqa: BLE001
        return None


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Fetch real MCP manifests for field testing")
    p.add_argument("--source", choices=["glama", "smithery"], required=True)
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--query", default="")
    p.add_argument("--out", required=True)
    args = p.parse_args(argv)

    if args.source == "glama":
        servers = fetch_glama(args.limit)
    else:
        servers = fetch_smithery(args.limit, args.query)

    with_tools = sum(1 for s in servers if s["tools"])
    doc = {
        "_note": f"Fetched from {args.source} via fieldtest/fetch.py. {len(servers)} servers, "
                 f"{with_tools} with tool definitions. Servers were not executed.",
        "servers": servers,
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    print(f"wrote {len(servers)} servers ({with_tools} with tools) -> {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
