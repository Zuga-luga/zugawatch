"""Tool-definition pinning — cryptographic rug-pull detection.

On first connection ZugaWatch hashes each tool's name, description, and input
schema into a lockfile. On every later session it re-hashes the live tools and
diffs against the lock. A changed description or schema for an already-trusted
tool is the "rug pull" attack: the server passed review, then silently mutated
its tool prose after install so the agent re-reads poisoned instructions.

The hash is canonical (sorted-key JSON) so semantically-identical definitions
produce identical hashes regardless of key ordering or whitespace.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


def _canonical(obj: Any) -> str:
    """Deterministic JSON for hashing — sorted keys, no insignificant space."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


@dataclass(frozen=True)
class ToolDef:
    """A tool as advertised by an MCP server (the part agents read)."""

    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)

    def digest(self) -> str:
        payload = _canonical(
            {
                "name": self.name,
                "description": self.description,
                "input_schema": self.input_schema,
            }
        )
        return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ToolPin:
    """A pinned tool digest, stored in the lockfile."""

    name: str
    digest: str

    @classmethod
    def of(cls, tool: ToolDef) -> "ToolPin":
        return cls(name=tool.name, digest=tool.digest())


class DriftKind(str, Enum):
    UNCHANGED = "unchanged"
    MUTATED = "mutated"  # description/schema changed -> rug-pull suspect
    ADDED = "added"      # new tool appeared since pinning
    REMOVED = "removed"  # previously-pinned tool vanished


@dataclass(frozen=True)
class Drift:
    name: str
    kind: DriftKind
    old_digest: str | None = None
    new_digest: str | None = None


class PinStore:
    """Load/save a zugawatch.lock pin file and pin a set of live tools."""

    def __init__(self, server: str, pins: dict[str, ToolPin] | None = None) -> None:
        self.server = server
        self.pins: dict[str, ToolPin] = pins or {}

    @classmethod
    def pin(cls, server: str, tools: list[ToolDef]) -> "PinStore":
        return cls(server, {t.name: ToolPin.of(t) for t in tools})

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": 1,
            "server": self.server,
            "pins": {name: asdict(p) for name, p in sorted(self.pins.items())},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PinStore":
        pins = {
            name: ToolPin(name=p["name"], digest=p["digest"])
            for name, p in data.get("pins", {}).items()
        }
        return cls(server=data.get("server", ""), pins=pins)

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2, sort_keys=True)
            fh.write("\n")

    @classmethod
    def load(cls, path: str) -> "PinStore":
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))


def diff_pins(store: PinStore, live: list[ToolDef]) -> list[Drift]:
    """Compare a pinned store against the live tool set. Empty list = clean."""
    live_by_name = {t.name: t for t in live}
    drifts: list[Drift] = []

    for name, pin in store.pins.items():
        tool = live_by_name.get(name)
        if tool is None:
            drifts.append(Drift(name, DriftKind.REMOVED, old_digest=pin.digest))
            continue
        new_digest = tool.digest()
        if new_digest != pin.digest:
            drifts.append(
                Drift(name, DriftKind.MUTATED, old_digest=pin.digest, new_digest=new_digest)
            )

    for name, tool in live_by_name.items():
        if name not in store.pins:
            drifts.append(Drift(name, DriftKind.ADDED, new_digest=tool.digest()))

    return drifts
