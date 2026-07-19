"""Call-chain anomaly engine.

This is the part no other open-source MCP tool has: instead of scanning a tool
*definition* once, ZugaWatch records the *sequence* of tool calls an agent makes
across one or more servers, builds a chain, and runs behavioural rules over it.
The dangerous patterns in agentic systems are emergent across calls — read a
secret, then send it somewhere, then delete the evidence — and are invisible to
any single-call check.

Capability tagging drives the rules. Tags come first from MCP tool annotations
(`readOnlyHint`, `destructiveHint`) and fall back to name/description heuristics
when a server omits annotations (most do).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


class Capability(str, Enum):
    READ = "read"            # reads data/files/secrets
    WRITE = "write"          # mutates local state
    NETWORK = "network"      # sends data off-box (exfil surface)
    DESTRUCTIVE = "destructive"  # deletes/overwrites irreversibly


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


_READ_HINTS = ("read", "get", "fetch", "list", "load", "cat", "view", "search", "query", "secret", "cred", "token", "env")
_NET_HINTS = ("http", "fetch", "post", "send", "upload", "webhook", "request", "url", "email", "slack", "discord", "publish", "exfil")
_WRITE_HINTS = ("write", "create", "update", "set", "put", "save", "append", "insert")
_DESTRUCTIVE_HINTS = ("delete", "remove", "drop", "destroy", "purge", "wipe", "rm", "truncate", "overwrite")


def classify(name: str, description: str = "", annotations: dict[str, Any] | None = None) -> set[Capability]:
    """Infer capability tags for a tool. Annotations win; names are the fallback."""
    caps: set[Capability] = set()
    ann = annotations or {}

    if ann.get("readOnlyHint") is True:
        caps.add(Capability.READ)
    if ann.get("destructiveHint") is True:
        caps.add(Capability.DESTRUCTIVE)

    text = f"{name} {description}".lower()
    if any(h in text for h in _DESTRUCTIVE_HINTS):
        caps.add(Capability.DESTRUCTIVE)
    if any(h in text for h in _NET_HINTS):
        caps.add(Capability.NETWORK)
    if any(h in text for h in _WRITE_HINTS):
        caps.add(Capability.WRITE)
    if any(h in text for h in _READ_HINTS):
        caps.add(Capability.READ)

    return caps


@dataclass
class CallEvent:
    """One tool invocation observed by the proxy."""

    seq: int                                  # monotonic position in the chain
    server: str
    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    result: str = ""                          # stringified result (summary ok)
    caps: set[Capability] = field(default_factory=set)

    def arg_blob(self) -> str:
        return " ".join(str(v) for v in self.args.values())


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    message: str
    evidence: list[int] = field(default_factory=list)  # CallEvent.seq values


class CallChain:
    """An ordered sequence of observed tool calls."""

    def __init__(self) -> None:
        self.events: list[CallEvent] = []

    def record(
        self,
        server: str,
        tool: str,
        args: dict[str, Any] | None = None,
        result: str = "",
        description: str = "",
        annotations: dict[str, Any] | None = None,
    ) -> CallEvent:
        ev = CallEvent(
            seq=len(self.events),
            server=server,
            tool=tool,
            args=args or {},
            result=result,
            caps=classify(tool, description, annotations),
        )
        self.events.append(ev)
        return ev


# A rule takes the whole chain and yields findings.
Rule = Callable[[CallChain], list[Finding]]


class AnomalyEngine:
    def __init__(self, rules: list[Rule] | None = None) -> None:
        from .rules.builtin import DEFAULT_RULES

        self.rules: list[Rule] = rules if rules is not None else list(DEFAULT_RULES)

    def analyze(self, chain: CallChain) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.rules:
            findings.extend(rule(chain))
        return findings
