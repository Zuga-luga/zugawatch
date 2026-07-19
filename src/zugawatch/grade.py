"""Roll findings + pin drift into a single A-F grade.

The letter grade mirrors how MCP registries (Glama, et al.) already present
server quality, so a ZugaWatch report is instantly legible to that audience.
"""

from __future__ import annotations

from dataclasses import dataclass

from .anomaly import Finding, Severity
from .pinning import Drift, DriftKind

_SEVERITY_PENALTY = {
    Severity.HIGH: 25,
    Severity.MEDIUM: 10,
    Severity.LOW: 3,
}

# A mutated pin is a rug-pull suspect — treated as a high-severity event.
_DRIFT_PENALTY = {
    DriftKind.MUTATED: 25,
    DriftKind.ADDED: 8,
    DriftKind.REMOVED: 5,
    DriftKind.UNCHANGED: 0,
}


@dataclass
class Grade:
    letter: str
    score: int
    findings: list[Finding]
    drifts: list[Drift]

    @property
    def passing(self) -> bool:
        return self.letter in ("A", "B")


def _letter(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def grade(findings: list[Finding], drifts: list[Drift] | None = None) -> Grade:
    drifts = drifts or []
    penalty = sum(_SEVERITY_PENALTY[f.severity] for f in findings)
    penalty += sum(_DRIFT_PENALTY[d.kind] for d in drifts)
    score = max(0, 100 - penalty)
    return Grade(letter=_letter(score), score=score, findings=findings, drifts=drifts)
