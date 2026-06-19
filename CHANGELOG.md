# Changelog

## 0.7.0
- **Eliminated the remaining static-scan false positives.** On the 183-server
  field sample the v0.6 rules still over-flagged via cross-tool steering (MCPP004)
  and bare-URL (MCPP005) matches — all benign (workflow ordering, doc links).
  - **Removed MCPP004** entirely: legitimate tools constantly reference other
    tools; a standalone "cross-tool steering" rule is ~100% false-positive and
    adversarial steering is already covered by MCPP002.
  - **MCPP005 narrowed** to fire only on an exfil verb adjacent to a URL
    ("send/upload/exfiltrate … https://…"), now HIGH severity. Excludes "post"
    (overloaded HTTP-method word).
  - Result: **0 findings, 0 false positives across all 183 servers** — no
    tool-poisoning in the sample. Regression tests cover doc-URL (clean) vs
    exfil-URL (flagged).

## 0.6.0
- **Real-world field test drove a major precision fix.** Scanned 183 live
  Smithery servers (172 with tools). Naive keyword rules produced 600+ false
  positives — legit auth/crypto/password-manager tools say "token", "password",
  "api key"; prompt-eng/eval tools say "system prompt", "jailbreak".
- Narrowed the static rules from *vocabulary* to *attack patterns*:
  - MCPP002 now requires an adversarial imperative (override / "do not tell the
    user"), not topical mentions of prompts/jailbreak.
  - MCPP003 now matches credential FILE targets (`~/.ssh/id_rsa`, `/etc/passwd`,
    `.aws/credentials`) and read-verb-near-`.env`, not the bare words
    password/token/api-key.
  - Result on the same 183-server sample: 600+ findings → 0 false positives,
    **no tool-poisoning found**. Regression tests lock the legit-vocab cases.
- Fetcher now de-duplicates servers across pages (200 rows → 129/183 unique).

## 0.5.0
- **Registry fetcher** (`fieldtest/fetch.py`, stdlib-only): pulls real MCP server
  manifests into the field-test format from Glama (public) or Smithery (free API
  key). Smithery serves real tools[]+inputSchema; Glama's tools[] is empty for
  most servers (documented). Verified live against both APIs. Servers are never
  executed — manifest JSON only.

## 0.4.0
- **Static manifest scanner** (`sentinel scan`, `mcp_sentinel.scan`): detects
  prompt-injection / tool-poisoning in published tool definitions without ever
  running the server — hidden/bidi unicode (MCPP001), injection/override language
  (MCPP002), secret/credential references (MCPP003), cross-tool steering
  (MCPP004), embedded URLs (MCPP005).
- **Field-test harness** (`fieldtest/run.py`): scans a set of server manifests
  (registry-export shaped) and writes `fieldtest/FINDINGS.md`. Seed corpus of 12
  representative servers; safe to point at real untrusted servers (text-only).

## 0.3.0
- **Empirical benchmark**: `benchmark/dataset.py` (122 labeled scenarios —
  attacks, benign, evasion) + `benchmark/run.py` harness reporting
  precision/recall/F1/FPR/latency, written to `benchmark/RESULTS.md`.
- Data-driven rule improvements surfaced by the benchmark:
  - SENT001 now detects **base64-encoded** exfiltration (recall 0.855→0.902).
  - SENT002 suppresses legitimate **in-place file edits** (read→overwrite same
    resource, same server), eliminating false positives (precision 0.887→1.000,
    FPR 0.098→0.000).
- Honest recall ceiling: a XOR-obfuscation evasion class is reported as missed,
  not hidden. Regression-guard test locks the metrics in CI.

## 0.2.1
- **`sentinel-action`** composite GitHub Action: one-line CI gate that installs
  Sentinel, runs the rug-pull/drift check and chain grade, fails the build on
  drift or grade C-or-below, and writes the grade to the job summary.

## 0.2.0
- **Transparent stdio proxy** (`sentinel proxy -- <server cmd>`): spawns a target
  MCP server, relays stdio faithfully, and records the live session into a graded
  report automatically — no manual chain JSON.
- Real-time rug-pull detection: tool-definition drift is flagged the moment
  `tools/list` returns, before the agent uses the tools.
- `ProxyObserver` (pure inspection) split from `StdioProxy` (IO pump) for testing.
- 18 tests (added pure observer + end-to-end proxy coverage).

## 0.1.0
- Tool-definition pinning + rug-pull/drift detection (SHA-256, canonical JSON).
- Call-chain anomaly engine with three rules: read-then-exfil (SENT001),
  destructive-after-read (SENT002), repetition-loop (SENT003).
- A–F grading, `sentinel` CLI (pin/verify/analyze/grade), MCP-server interface.
- Registry metadata: MIT, CI, smithery.yaml, server.json, icon.svg.
