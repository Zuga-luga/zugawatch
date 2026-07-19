"""Built-in call-chain anomaly rules.

Each rule inspects the ordered chain and returns findings. These three cover the
emergent agentic attack patterns that single-call scanners cannot see:

  SENT001  read-then-exfiltrate   a read tool's output flows into a later
                                  network call (data leaving the box)
  SENT002  destructive-after-read an irreversible delete/overwrite follows a
                                  read, especially across a server boundary
  SENT003  repetition-loop        the same tool+args fires repeatedly (runaway
                                  agent / amplification)
"""

from __future__ import annotations

import base64

from ..anomaly import CallChain, Capability, Finding, Severity

_OVERWRITE_HINTS = ("overwrite", "update", "edit", "save", "patch", "write")


def _b64(s: str) -> str:
    try:
        return base64.b64encode(s.encode()).decode()
    except (ValueError, UnicodeError):
        return ""


def _flows(token: str, later_blob: str) -> bool:
    if len(token) >= 8 and token in later_blob:
        return True
    enc = _b64(token)  # catch base64-encoded exfiltration
    if len(enc) >= 8 and enc in later_blob:
        return True
    return False


def _result_flows_into(result: str, later_blob: str) -> bool:
    """Heuristic data-flow: a non-trivial chunk of an earlier result reappears
    downstream — verbatim OR base64-encoded. (Encryption/XOR obfuscation still
    evades this; see benchmark RESULTS for the honest recall ceiling.)"""
    token = (result or "").strip()
    if len(token) < 8:
        return False
    if _flows(token, later_blob):
        return True
    for line in token.splitlines():
        line = line.strip()
        if len(line) >= 8 and _flows(line, later_blob):
            return True
    return False


def rule_read_then_exfil(chain: CallChain) -> list[Finding]:
    findings: list[Finding] = []
    for i, src in enumerate(chain.events):
        if Capability.READ not in src.caps or not src.result:
            continue
        for dst in chain.events[i + 1 :]:
            if Capability.NETWORK not in dst.caps:
                continue
            if _result_flows_into(src.result, dst.arg_blob()):
                findings.append(
                    Finding(
                        rule_id="SENT001",
                        severity=Severity.HIGH,
                        message=(
                            f"Data read by '{src.tool}' (seq {src.seq}) flows into "
                            f"network tool '{dst.tool}' (seq {dst.seq}) - possible exfiltration."
                        ),
                        evidence=[src.seq, dst.seq],
                    )
                )
    return findings


def rule_destructive_after_read(chain: CallChain) -> list[Finding]:
    findings: list[Finding] = []
    last_read = None
    for ev in chain.events:
        if Capability.READ in ev.caps:
            last_read = ev
        if Capability.DESTRUCTIVE in ev.caps and last_read is not None:
            cross = ev.server != last_read.server
            # Suppress legitimate in-place edits: read a resource, then
            # overwrite/update the SAME resource on the SAME server. The
            # dangerous pattern is destroying something OTHER than what was
            # read (cover-tracks) or reaching across a server boundary.
            same_target = bool(
                {str(v) for v in ev.args.values()} & {str(v) for v in last_read.args.values()}
            )
            is_overwrite = any(h in ev.tool.lower() for h in _OVERWRITE_HINTS)
            if not cross and same_target and is_overwrite:
                continue
            findings.append(
                Finding(
                    rule_id="SENT002",
                    severity=Severity.HIGH if cross else Severity.MEDIUM,
                    message=(
                        f"Destructive tool '{ev.tool}' (seq {ev.seq}) runs after read "
                        f"'{last_read.tool}' (seq {last_read.seq})"
                        + (" across a server boundary" if cross else "")
                        + " - read-then-destroy pattern."
                    ),
                    evidence=[last_read.seq, ev.seq],
                )
            )
    return findings


def rule_repetition_loop(chain: CallChain, threshold: int = 3) -> list[Finding]:
    findings: list[Finding] = []
    seen: dict[tuple[str, str, str], list[int]] = {}
    for ev in chain.events:
        key = (ev.server, ev.tool, ev.arg_blob())
        seen.setdefault(key, []).append(ev.seq)
    for (server, tool, _blob), seqs in seen.items():
        if len(seqs) >= threshold:
            findings.append(
                Finding(
                    rule_id="SENT003",
                    severity=Severity.MEDIUM,
                    message=(
                        f"Tool '{tool}' on '{server}' called {len(seqs)}x with identical "
                        f"arguments — runaway loop / amplification."
                    ),
                    evidence=list(seqs),
                )
            )
    return findings


DEFAULT_RULES = [
    rule_read_then_exfil,
    rule_destructive_after_read,
    rule_repetition_loop,
]
