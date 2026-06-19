"""Static manifest scanner — analyse a server's published tool definitions for
prompt-injection / tool-poisoning without ever running the server.

This is the safe way to audit real-world servers at scale: registries publish
each server's tool list (name + description + input schema), and the poisoning
attack lives *in that prose* — adversarial instructions the agent reads. We scan
the text; we never spawn the server.

Findings reuse `anomaly.Finding` so they flow through the same `grade()` path as
the runtime rules.
"""

from __future__ import annotations

import re
from typing import Any

from .anomaly import Finding, Severity
from .pinning import ToolDef

# Zero-width and bidirectional control characters — used to hide instructions.
_HIDDEN = re.compile(r"[​-‏‪-‮⁠⁦-⁩﻿]")

# Adversarial IMPERATIVES only — not topical mentions. Real tools legitimately
# discuss "system prompt"/"jailbreak" (prompt-eng + eval servers), so matching
# those vocab words produces false positives on real registries. We require an
# instruction to override or to hide behaviour from the user.
_INJECTION = re.compile(
    r"\b(ignore\s+(all\s+|the\s+)?(previous|above|prior)\s+(instructions|rules|prompts?)"
    r"|disregard\s+(the\s+)?(previous|above|prior|all)\s+(instructions|rules)"
    r"|do\s+not\s+(tell|inform|mention|reveal)\s+(the\s+)?user"
    r"|without\s+(telling|informing|alerting)\s+(the\s+)?user"
    r"|override\s+(the\s+)?(rules|instructions|system))\b",
    re.IGNORECASE,
)

# Credential FILE targets / exfil paths only — NOT the words "password" / "token"
# / "api key", which legitimate auth, crypto, and password-manager tools use
# constantly (the #1 source of false positives in the real-world field test).
_SECRETS = re.compile(
    r"(~/\.ssh\b|id_rsa\b|id_ed25519\b|/etc/passwd\b|\.aws/credentials\b"
    r"|\.ssh/[\w.]*key|(read|exfiltrate|send|include|leak)\s+[^.\n]{0,40}\.env\b)",
    re.IGNORECASE,
)

# NOTE: a generic "cross-tool steering" rule (MCPP004) was REMOVED in v0.7 after
# the field test showed it was ~100% false positives — legitimate tools routinely
# describe ordering ("call before retrying", "for subsequent calls"). Adversarial
# steering that hides from the user is already caught by MCPP002. A standalone
# rule that only fires on benign text is worse than no rule.

# A bare URL in a description is normal (docs/data links). Only flag a URL paired
# with an exfiltration imperative — "send/post/upload ... to https://...".
# "post" is excluded — it's overloaded as an HTTP-method word ("Redeem at POST
# https://...") and produced a false positive. Keep only verbs that unambiguously
# mean "send data out".
_EXFIL_URL = re.compile(
    r"\b(send|upload|exfiltrate|ex-?filtrate|leak|deliver|transmit)\b[^.\n]{0,60}?https?://[^\s\"'<>]+",
    re.IGNORECASE,
)


def _text(tool: ToolDef) -> str:
    return f"{tool.name}\n{tool.description}\n{tool.input_schema}"


def scan_tool(tool: ToolDef) -> list[Finding]:
    findings: list[Finding] = []
    text = _text(tool)

    if _HIDDEN.search(text):
        findings.append(Finding("MCPP001", Severity.HIGH,
            f"Tool '{tool.name}' description contains hidden/zero-width or bidi control characters."))
    if _INJECTION.search(text):
        findings.append(Finding("MCPP002", Severity.HIGH,
            f"Tool '{tool.name}' description contains prompt-injection / override language."))
    if _SECRETS.search(text):
        findings.append(Finding("MCPP003", Severity.HIGH,
            f"Tool '{tool.name}' description references secrets/credentials (e.g. SSH keys, .env, tokens)."))
    if _EXFIL_URL.search(tool.description or ""):
        findings.append(Finding("MCPP005", Severity.HIGH,
            f"Tool '{tool.name}' description instructs sending data to an external URL — exfiltration sink."))
    return findings


def scan_manifest(tools: list[ToolDef]) -> list[Finding]:
    out: list[Finding] = []
    for t in tools:
        out.extend(scan_tool(t))
    return out


def tools_from_json(data: list[dict[str, Any]]) -> list[ToolDef]:
    return [
        ToolDef(t.get("name", ""), t.get("description", ""), t.get("inputSchema", t.get("input_schema", {})) or {})
        for t in data
    ]
