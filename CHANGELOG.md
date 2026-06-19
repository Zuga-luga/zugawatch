# Changelog

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
