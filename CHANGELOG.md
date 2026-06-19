# Changelog

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
