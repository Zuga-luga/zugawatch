"""zugawatch CLI.

    zugawatch pin     <tools.json> --lock zugawatch.lock
    zugawatch verify  <tools.json> --lock zugawatch.lock      # rug-pull check
    zugawatch analyze <chain.json>                            # call-chain anomalies
    zugawatch grade   <chain.json> [--lock zugawatch.lock --tools tools.json]

Input formats are plain JSON so the CLI works against any MCP server's
captured output without a live connection (and so CI can gate on a fixture).
`tools.json`  : [{"name","description","input_schema"}, ...]
`chain.json`  : [{"server","tool","args","result","description","annotations"}, ...]

Exit code is 0 for grade A/B, 1 otherwise — drop it straight into CI.
"""

from __future__ import annotations

import argparse
import json
import sys

from .anomaly import AnomalyEngine, CallChain
from .grade import grade as compute_grade
from .pinning import PinStore, ToolDef, diff_pins


def _load(path: str):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _tools(path: str) -> list[ToolDef]:
    return [
        ToolDef(
            name=t["name"],
            description=t.get("description", ""),
            input_schema=t.get("input_schema", {}),
        )
        for t in _load(path)
    ]


def _chain(path: str) -> CallChain:
    chain = CallChain()
    for c in _load(path):
        chain.record(
            server=c.get("server", "unknown"),
            tool=c["tool"],
            args=c.get("args", {}),
            result=c.get("result", ""),
            description=c.get("description", ""),
            annotations=c.get("annotations"),
        )
    return chain


def cmd_pin(args) -> int:
    store = PinStore.pin(args.server, _tools(args.tools))
    store.save(args.lock)
    print(f"pinned {len(store.pins)} tools -> {args.lock}")
    return 0


def cmd_verify(args) -> int:
    store = PinStore.load(args.lock)
    drifts = diff_pins(store, _tools(args.tools))
    if not drifts:
        print("OK — no drift; all pinned tools unchanged.")
        return 0
    for d in drifts:
        print(f"DRIFT [{d.kind.value}] {d.name}")
    mutated = any(d.kind.value == "mutated" for d in drifts)
    print(f"\n{len(drifts)} drift(s)" + ("  *** RUG-PULL SUSPECT ***" if mutated else ""))
    return 1


def cmd_analyze(args) -> int:
    findings = AnomalyEngine().analyze(_chain(args.chain))
    if not findings:
        print("OK — no call-chain anomalies.")
        return 0
    for f in findings:
        print(f"[{f.severity.value.upper():6}] {f.rule_id}  {f.message}")
    return 1


def cmd_scan(args) -> int:
    from .scan import scan_manifest, tools_from_json

    findings = scan_manifest(tools_from_json(_load(args.manifest)))
    g = compute_grade(findings, [])
    print(f"GRADE {g.letter}  ({g.score}/100)  {len(findings)} finding(s)")
    for f in findings:
        print(f"  [{f.severity.value.upper():6}] {f.rule_id}  {f.message}")
    return 0 if g.passing else 1


def cmd_proxy(args) -> int:
    from .proxy import StdioProxy

    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("usage: zugawatch proxy [--lock L] [--report R] -- <server command...>", file=sys.stderr)
        return 2
    return StdioProxy(
        command=command,
        lock_path=args.lock,
        report_path=args.report,
        server_name=args.name,
    ).run()


def cmd_grade(args) -> int:
    findings = AnomalyEngine().analyze(_chain(args.chain))
    drifts = []
    if args.lock and args.tools:
        drifts = diff_pins(PinStore.load(args.lock), _tools(args.tools))
    g = compute_grade(findings, drifts)
    print(f"GRADE {g.letter}  ({g.score}/100)  findings={len(findings)} drifts={len(drifts)}")
    for f in findings:
        print(f"  [{f.severity.value.upper():6}] {f.rule_id}  {f.message}")
    return 0 if g.passing else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="zugawatch", description="Runtime MCP call-chain anomaly monitor")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("pin", help="pin tool definitions to a lockfile")
    sp.add_argument("tools")
    sp.add_argument("--lock", default="zugawatch.lock")
    sp.add_argument("--server", default="default")
    sp.set_defaults(func=cmd_pin)

    sv = sub.add_parser("verify", help="check live tools against the lockfile (rug-pull)")
    sv.add_argument("tools")
    sv.add_argument("--lock", default="zugawatch.lock")
    sv.set_defaults(func=cmd_verify)

    sa = sub.add_parser("analyze", help="run anomaly rules over a recorded call-chain")
    sa.add_argument("chain")
    sa.set_defaults(func=cmd_analyze)

    sc = sub.add_parser("scan", help="statically scan a tool manifest for injection / tool-poisoning")
    sc.add_argument("manifest", help="JSON array of tool definitions")
    sc.set_defaults(func=cmd_scan)

    pr = sub.add_parser(
        "proxy",
        help="run a target MCP server through ZugaWatch, recording the live session",
    )
    pr.add_argument("--lock", help="pin/verify tool defs against this lockfile (rug-pull check)")
    pr.add_argument("--report", help="write the graded JSON report here at shutdown")
    pr.add_argument("--name", default="proxied", help="label for the proxied server")
    pr.add_argument("command", nargs=argparse.REMAINDER, help="-- <server command...>")
    pr.set_defaults(func=cmd_proxy)

    sg = sub.add_parser("grade", help="produce an A-F grade from a chain (+ optional pins)")
    sg.add_argument("chain")
    sg.add_argument("--lock")
    sg.add_argument("--tools")
    sg.set_defaults(func=cmd_grade)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
