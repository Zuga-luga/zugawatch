"""Transparent stdio proxy — records a live MCP session automatically.

Sentinel spawns the real MCP server as a subprocess and sits in the middle of
the stdio JSON-RPC stream:

    client ──stdin──> [ ProxyObserver ] ──stdin──> target server
    client <─stdout── [ ProxyObserver ] <─stdout── target server

It forwards every byte faithfully (the client and server are unaware) while
watching the traffic:

  * on the `tools/list` response it captures the live tool definitions, pins
    them on first run, and on later runs flags drift (the runtime rug-pull
    catch — verification happens *before* the agent uses the tools);
  * on each `tools/call` request it records the tool + arguments, and on the
    matching response it records the result, building a `CallChain`;
  * at shutdown it runs the anomaly engine and writes a graded report.

The MCP stdio transport is newline-delimited JSON-RPC, one message per line
with no embedded newlines, so line-based relaying is faithful.

`ProxyObserver` holds all inspection logic and is pure/unit-testable; `StdioProxy`
is just the IO pump around it.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from typing import Any

from .anomaly import AnomalyEngine, CallChain
from .grade import grade as compute_grade
from .pinning import PinStore, ToolDef, diff_pins


def _extract_text(result: Any) -> str:
    """Pull a string summary out of an MCP tools/call result object."""
    if isinstance(result, dict):
        content = result.get("content")
        if isinstance(content, list):
            parts = [c.get("text", "") for c in content if isinstance(c, dict) and c.get("type") == "text"]
            if parts:
                return "\n".join(parts)
        return json.dumps(result, separators=(",", ":"))
    return "" if result is None else str(result)


@dataclass
class ProxyObserver:
    """Pure inspection state for one proxied session. No IO."""

    server_name: str = "proxied"
    lock_path: str | None = None

    chain: CallChain = field(default_factory=CallChain)
    pending: dict[Any, dict[str, Any]] = field(default_factory=dict)   # rpc id -> {name,args}
    tool_meta: dict[str, dict[str, Any]] = field(default_factory=dict)  # name -> {description,annotations}
    drift_alerts: list[str] = field(default_factory=list)

    def on_client_message(self, msg: dict[str, Any]) -> None:
        """A request flowing client -> server."""
        if msg.get("method") == "tools/call":
            params = msg.get("params") or {}
            rpc_id = msg.get("id")
            if rpc_id is not None:
                self.pending[rpc_id] = {
                    "name": params.get("name", "unknown"),
                    "args": params.get("arguments", {}) or {},
                }

    def on_server_message(self, msg: dict[str, Any]) -> None:
        """A response flowing server -> client."""
        result = msg.get("result")
        if not isinstance(result, dict):
            # could still be a tools/call result that's a list/scalar
            result = {"_": result} if "id" in msg and msg["id"] in self.pending else None

        # tools/list response: {"result": {"tools": [...]}}
        if isinstance(msg.get("result"), dict) and "tools" in msg["result"]:
            self._ingest_tools(msg["result"]["tools"])
            return

        rpc_id = msg.get("id")
        if rpc_id in self.pending:
            call = self.pending.pop(rpc_id)
            meta = self.tool_meta.get(call["name"], {})
            self.chain.record(
                server=self.server_name,
                tool=call["name"],
                args=call["args"],
                result=_extract_text(msg.get("result")),
                description=meta.get("description", ""),
                annotations=meta.get("annotations"),
            )

    def _ingest_tools(self, tools: list[dict[str, Any]]) -> None:
        live: list[ToolDef] = []
        for t in tools:
            name = t.get("name", "")
            self.tool_meta[name] = {
                "description": t.get("description", ""),
                "annotations": t.get("annotations"),
            }
            live.append(ToolDef(name, t.get("description", ""), t.get("inputSchema", t.get("input_schema", {})) or {}))

        if not self.lock_path:
            return
        try:
            store = PinStore.load(self.lock_path)
        except FileNotFoundError:
            PinStore.pin(self.server_name, live).save(self.lock_path)
            return
        for d in diff_pins(store, live):
            tag = "RUG-PULL SUSPECT" if d.kind.value == "mutated" else d.kind.value
            self.drift_alerts.append(f"[{tag}] {d.name}")

    def report(self) -> dict[str, Any]:
        findings = AnomalyEngine().analyze(self.chain)
        g = compute_grade(findings, [])
        return {
            "server": self.server_name,
            "calls": len(self.chain.events),
            "grade": g.letter,
            "score": g.score,
            "drift_alerts": self.drift_alerts,
            "findings": [
                {"rule": f.rule_id, "severity": f.severity.value, "message": f.message, "evidence": f.evidence}
                for f in findings
            ],
        }


class StdioProxy:
    """Spawn `command` and relay stdio through a ProxyObserver."""

    def __init__(
        self,
        command: list[str],
        lock_path: str | None = None,
        report_path: str | None = None,
        server_name: str = "proxied",
    ) -> None:
        self.command = command
        self.report_path = report_path
        self.observer = ProxyObserver(server_name=server_name, lock_path=lock_path)
        self._lock = threading.Lock()

    @staticmethod
    def _parse(line: bytes) -> dict[str, Any] | None:
        try:
            obj = json.loads(line)
            return obj if isinstance(obj, dict) else None
        except (ValueError, UnicodeDecodeError):
            return None

    def _pump(self, src, dst, on_message) -> None:
        for line in iter(src.readline, b""):
            dst.write(line)
            dst.flush()
            obj = self._parse(line)
            if obj is not None:
                with self._lock:
                    on_message(obj)
        try:
            dst.close()
        except OSError:
            pass

    def run(self) -> int:
        proc = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            bufsize=0,
        )
        up = threading.Thread(
            target=self._pump, args=(sys.stdin.buffer, proc.stdin, self.observer.on_client_message), daemon=True
        )
        down = threading.Thread(
            target=self._pump, args=(proc.stdout, sys.stdout.buffer, self.observer.on_server_message), daemon=True
        )
        up.start()
        down.start()
        code = proc.wait()
        down.join(timeout=2)

        report = self.observer.report()
        self._emit(report)
        return code

    def _emit(self, report: dict[str, Any]) -> None:
        if self.report_path:
            with open(self.report_path, "w", encoding="utf-8") as fh:
                json.dump(report, fh, indent=2)
                fh.write("\n")
        line = f"[sentinel] {report['calls']} calls  grade {report['grade']} ({report['score']}/100)"
        if report["drift_alerts"]:
            line += "  DRIFT: " + ", ".join(report["drift_alerts"])
        print(line, file=sys.stderr)
        for f in report["findings"]:
            print(f"[sentinel] {f['severity'].upper()} {f['rule']} {f['message']}", file=sys.stderr)
