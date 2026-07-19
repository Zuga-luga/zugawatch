"""Field-test harness — run ZugaWatch's static manifest scanner across a set of
real-world server manifests and write a findings report.

    python fieldtest/run.py [path/to/servers.json]

Input is `{ "servers": [ { "name", "tools": [ {name, description, inputSchema} ] } ] }`
— the same shape registries (Glama/Smithery/official) expose. The default seed
(`fieldtest/servers.json`) is representative, not live; point it at a registry
export to scan real servers. ZugaWatch never runs the servers — it only reads the
published tool prose, so scanning untrusted servers at scale is safe.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from zugawatch.grade import grade as compute_grade  # noqa: E402
from zugawatch.scan import scan_manifest, tools_from_json  # noqa: E402


def run(path: Path):
    data = json.loads(path.read_text(encoding="utf-8"))
    servers = data["servers"] if isinstance(data, dict) else data
    rows = []
    flagged_tools = 0
    by_rule: dict[str, int] = {}
    for s in servers:
        tools = tools_from_json(s.get("tools", []))
        findings = scan_manifest(tools)
        g = compute_grade(findings, [])
        for f in findings:
            by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
        flagged_tools += len({f.message.split("'")[1] for f in findings if "'" in f.message})
        rows.append({"name": s["name"], "tools": len(tools), "grade": g.letter,
                     "score": g.score, "findings": findings})
    return rows, by_rule, flagged_tools


def render(rows, by_rule, flagged_tools) -> str:
    n = len(rows)
    clean = sum(1 for r in rows if r["grade"] in ("A", "B"))
    out = ["# MCP ZugaWatch — Field-Test Findings\n",
           "Static scan of published tool manifests (servers are never executed).\n",
           f"**{n} servers scanned** · {clean} clean (A/B) · {n - clean} flagged · "
           f"{flagged_tools} tool(s) with findings\n",
           "## Per-server\n",
           "| Server | Tools | Grade | Top finding |",
           "|---|---|---|---|"]
    for r in sorted(rows, key=lambda x: x["score"]):
        top = r["findings"][0].message if r["findings"] else "—"
        if len(top) > 90:
            top = top[:87] + "..."
        out.append(f"| {r['name']} | {r['tools']} | {r['grade']} | {top} |")
    out.append("\n## Findings by rule\n")
    out.append("| Rule | Count | Meaning |")
    out.append("|---|---|---|")
    meaning = {
        "MCPP001": "hidden/zero-width or bidi control chars",
        "MCPP002": "prompt-injection / override language",
        "MCPP003": "references secrets/credentials",
        "MCPP004": "cross-tool steering",
        "MCPP005": "embedded URL (exfil/instruction sink)",
    }
    for rule in sorted(by_rule):
        out.append(f"| {rule} | {by_rule[rule]} | {meaning.get(rule, '')} |")
    return "\n".join(out) + "\n"


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    path = Path(argv[0]) if argv else (ROOT / "fieldtest" / "servers.json")
    rows, by_rule, flagged = run(path)
    md = render(rows, by_rule, flagged)
    (ROOT / "fieldtest" / "FINDINGS.md").write_text(md, encoding="utf-8")
    print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
