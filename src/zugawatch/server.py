"""ZugaWatch as an MCP server — so an agent can audit other servers itself.

Run:  zugawatch-mcp   (requires the optional `server` extra: pip install zugawatch[server])

The tool descriptions here are deliberately written to the Glama TDQS rubric:
each states what it does, when to use it, when NOT to, side effects, and exact
parameter semantics. Annotations (readOnlyHint/destructiveHint) are set for the
Smithery rubric. All ZugaWatch tools are read-only and have no side effects.
"""

from __future__ import annotations

import json

from .anomaly import AnomalyEngine, CallChain
from .grade import grade as compute_grade
from .pinning import PinStore, ToolDef, diff_pins


def _build_chain(events: list[dict]) -> CallChain:
    chain = CallChain()
    for c in events:
        chain.record(
            server=c.get("server", "unknown"),
            tool=c["tool"],
            args=c.get("args", {}),
            result=c.get("result", ""),
            description=c.get("description", ""),
            annotations=c.get("annotations"),
        )
    return chain


# --- pure tool implementations (importable + unit-testable without the SDK) ---

def tool_analyze_chain(events: list[dict]) -> dict:
    findings = AnomalyEngine().analyze(_build_chain(events))
    return {
        "anomalies": [
            {"rule": f.rule_id, "severity": f.severity.value, "message": f.message, "evidence": f.evidence}
            for f in findings
        ]
    }


def tool_check_drift(pinned: dict, live_tools: list[dict]) -> dict:
    store = PinStore.from_dict(pinned)
    live = [ToolDef(t["name"], t.get("description", ""), t.get("input_schema", {})) for t in live_tools]
    drifts = diff_pins(store, live)
    return {"drifts": [{"name": d.name, "kind": d.kind.value} for d in drifts]}


def tool_grade_server(events: list[dict], pinned: dict | None = None, live_tools: list[dict] | None = None) -> dict:
    findings = AnomalyEngine().analyze(_build_chain(events))
    drifts = []
    if pinned and live_tools:
        live = [ToolDef(t["name"], t.get("description", ""), t.get("input_schema", {})) for t in live_tools]
        drifts = diff_pins(PinStore.from_dict(pinned), live)
    g = compute_grade(findings, drifts)
    return {"letter": g.letter, "score": g.score, "passing": g.passing,
            "findings": len(findings), "drifts": len(drifts)}


def main() -> None:  # pragma: no cover - requires the mcp SDK + a live client
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # pragma: no cover
        raise SystemExit(
            "The MCP server entrypoint needs the optional extra: pip install zugawatch[server]"
        ) from exc

    mcp = FastMCP("zugawatch")

    @mcp.tool(annotations={"readOnlyHint": True})
    def analyze_chain(events_json: str) -> str:
        """Analyze a recorded MCP call-chain for emergent anomalies (read-then-
        exfiltrate, destructive-after-read, runaway loops). Use this AFTER an
        agent run to audit what a server actually did across multiple tool calls.
        Do NOT use it to scan a single static tool definition — use check_drift
        for that. Read-only; no side effects.

        events_json: a JSON array of call events, each {"server","tool","args",
        "result","description","annotations"}. Returns a JSON object {"anomalies":[...]}.
        """
        return json.dumps(tool_analyze_chain(json.loads(events_json)))

    @mcp.tool(annotations={"readOnlyHint": True})
    def check_drift(pinned_json: str, live_tools_json: str) -> str:
        """Detect tool-definition drift ("rug pull") by diffing a previously
        pinned lockfile against a server's current tool list. Use this on every
        new session before trusting a server. Do NOT use it for behavioural
        analysis — use analyze_chain. Read-only; no side effects.

        pinned_json: the saved zugawatch.lock object. live_tools_json: JSON array
        of the server's current tools. Returns {"drifts":[{"name","kind"}]}.
        """
        return json.dumps(tool_check_drift(json.loads(pinned_json), json.loads(live_tools_json)))

    @mcp.tool(annotations={"readOnlyHint": True})
    def grade_server(events_json: str) -> str:
        """Produce a single A-F trust grade for a server from a recorded
        call-chain. Use this for a one-glance verdict in dashboards or CI. Do
        NOT treat the grade as a substitute for reading individual findings on
        a failing server. Read-only; no side effects.

        events_json: JSON array of call events (see analyze_chain). Returns
        {"letter","score","passing","findings","drifts"}.
        """
        return json.dumps(tool_grade_server(json.loads(events_json)))

    mcp.run()


if __name__ == "__main__":  # pragma: no cover
    main()
