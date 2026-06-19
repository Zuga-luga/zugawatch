# MCP Sentinel

**Runtime call-chain anomaly monitor for MCP servers.** Sentinel watches what an
MCP server *actually does* across a whole agent session — not just what a single
tool definition says — and catches the emergent attacks that static scanners
miss.

[![CI](https://github.com/Zuga-luga/mcp-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/Zuga-luga/mcp-sentinel/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org)

## Why this exists

There are already a dozen MCP *static* scanners — they read a server's tool
definitions once and flag injection strings. But the real damage in agentic
systems is **emergent across calls**: read a secret → POST it to a URL → delete
the log. Each call looks fine alone. No open-source tool sequences the calls and
flags the *pattern*. Sentinel does.

It also closes the **rug-pull** gap: a server passes review, then silently
mutates its tool descriptions after install so the agent re-reads poisoned
instructions next session. Sentinel cryptographically pins every tool definition
and flags any post-approval change.

| | static scanners | **Sentinel** |
|---|:--:|:--:|
| Scan tool definitions | ✅ | ✅ |
| Cryptographic pin + rug-pull / drift detection | ✗ | ✅ |
| **Call-chain behavioural anomaly detection** | ✗ | ✅ |
| A–F grade per server | some | ✅ |
| Ships as an MCP server (agent can self-audit) | rare | ✅ |
| GitHub Action / CI gate | some | ✅ |

## Install

```sh
pip install mcp-sentinel          # zero-dependency core (CLI)
pip install "mcp-sentinel[server]"  # + the MCP-server entrypoint
```

## Use

### 1. Pin a server's tools, then detect rug-pulls

```sh
sentinel pin examples/tools.json --lock sentinel.lock   # trust on first use
sentinel verify examples/tools.json --lock sentinel.lock # later sessions
# DRIFT [mutated] get_weather   *** RUG-PULL SUSPECT ***   (exit 1)
```

### 2. Analyze a recorded call-chain

```sh
sentinel analyze examples/chain_exfil.json
# [HIGH  ] SENT001  Data read by 'read_file' (seq 0) flows into network tool 'http_post' (seq 1) - possible exfiltration.
# [HIGH  ] SENT002  Destructive tool 'delete_file' (seq 2) runs after read 'read_file' (seq 0) across a server boundary - read-then-destroy pattern.
```

### 3. Grade it (CI gate — exit 0 for A/B, 1 otherwise)

```sh
sentinel grade examples/chain_exfil.json
# GRADE D  (50/100)  findings=2 drifts=0   (exit 1)
```

### 4. Transparent proxy — record a live session automatically

Wrap any MCP server. Sentinel spawns it, relays stdio faithfully (the client and
server don't know it's there), and records the real session — no manual JSON:

```sh
sentinel proxy --lock sentinel.lock --report report.json -- npx -y @some/mcp-server
```

Point your MCP client at `sentinel proxy -- <server cmd>` instead of the server
directly. On shutdown it writes a graded JSON report and prints a summary to
stderr; tool-definition drift is flagged the moment `tools/list` comes back —
the runtime rug-pull catch, *before* the agent uses the tools.

### 5. Statically scan a server's manifest (no execution)

Audit a server's published tool definitions for prompt-injection / tool-poisoning
without ever running it — the safe way to vet untrusted servers at scale:

```sh
sentinel scan manifest.json
# GRADE D  (50/100)  2 finding(s)
#   [HIGH  ] MCPP002  Tool 'add' description contains prompt-injection / override language.
```

Run it across a whole registry export with `python fieldtest/run.py <servers.json>`
→ writes `fieldtest/FINDINGS.md`.

### 6. GitHub Action — one-line CI gate

```yaml
# .github/workflows/sentinel.yml
- uses: Zuga-luga/mcp-sentinel@v0.4
  with:
    tools: examples/tools.json        # rug-pull check (pins on first run)
    chain: examples/chain_exfil.json  # grade the recorded session
```

Fails the build on tool-definition drift or grade C-or-below, and writes the
grade to the job summary. See `examples/workflow.yml`.

### 7. As an MCP server (agents self-audit)

```sh
sentinel-mcp     # exposes analyze_chain, check_drift, grade_server
```

## Built-in anomaly rules

| ID | Pattern | Severity |
|----|---------|----------|
| `SENT001` | read-then-exfiltrate — read output flows into a later network call | HIGH |
| `SENT002` | destructive-after-read — irreversible delete/overwrite following a read (HIGH across a server boundary) | HIGH / MED |
| `SENT003` | repetition-loop — identical tool+args fired repeatedly (runaway agent) | MED |

Rules are plain functions `(CallChain) -> list[Finding]`; add your own by passing
them to `AnomalyEngine(rules=[...])`.

## Benchmark — measured, not claimed

Security tools live or die on data. Sentinel ships a labeled corpus
(`benchmark/dataset.py`, 122 scenarios: attacks, benign, and evasion) and an
evaluation harness (`benchmark/run.py`) that reports precision / recall / F1 /
false-positive-rate. Run it yourself: `python benchmark/run.py`.

| Metric | Value |
|---|---|
| Precision | **1.000** |
| Recall | **0.902** |
| F1 | **0.948** |
| False-positive rate | **0.000** |
| Latency p95 | **< 0.02 ms / scenario** |

Recall is deliberately **not** 1.0: the corpus includes a XOR-obfuscated
exfiltration class that the current heuristics cannot see, and the harness
reports it as a miss rather than hiding it. That recall ceiling is the roadmap.
The rule improvements that took precision 0.887→1.000 and recall 0.855→0.902
(base64-aware data-flow; suppressing legitimate in-place file edits) were both
driven by failures this benchmark surfaced. Full report: `benchmark/RESULTS.md`.

## Design

```
agent ──calls──> [ Sentinel ] ──forwards──> target MCP server
                     │
                     ├─ pin tool defs on first connect (sentinel.lock)
                     ├─ record every call into a CallChain
                     └─ run anomaly rules + grade
```

Capability tags (`read` / `write` / `network` / `destructive`) drive the rules.
They come from MCP tool annotations (`readOnlyHint`, `destructiveHint`) and fall
back to name/description heuristics when a server omits them — which most do.

## Status

v0.4 — pinning, three call-chain anomaly rules, the static manifest scanner,
grading, CLI, MCP-server interface, transparent stdio proxy, GitHub Action, an
empirical benchmark, and a field-test harness are all implemented and tested
(26 tests, CI-gated metrics).

Roadmap: defeat the XOR/encryption exfil evasion class (entropy + length
heuristics), cross-server data-pivot and privilege-escalation rules, SARIF
output, and PyPI publish.

## License

MIT © Antonio Delgado
