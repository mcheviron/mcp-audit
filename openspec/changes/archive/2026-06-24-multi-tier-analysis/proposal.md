## Why

mcp-audit's current analysis is single-pass regex and static pattern matching — equivalent to MCP Verify's Layer 1 only. Competitors MCP Verify (3-tier: Fast Rules → Heuristic → LLM) and MCTS (dual scoring engine with multi-factor v2) provide graduated, depth-ranked analysis. MCP Verify's heuristic layer catches anomalous patterns missed by regex (e.g., unusually long descriptions, inconsistent naming, missing parameter docs). MCTS's multi-factor scoring provides corpus-calibrated risk scores usable as CI gates. mcp-audit's flat severity model cannot express confidence-weighted risk.

## What Changes

- Add a **heuristic scoring engine** (Layer 2) that evaluates tool descriptions and schemas using weighted anomaly detectors: description entropy, parameter count anomalies, naming convention consistency, schema complexity scoring
- Add a **multi-factor risk scoring** system producing normalized 0-100 scores from independent factors: typosquat distance, CVE count, capability breadth, description quality, network exposure
- Integrate scoring into the scan pipeline with **CI gate flags** (`--min-security-score`, `--max-absolute-risk`)
- Extend the report formatter to display heuristic risk scores alongside severity levels
- Define a **Layer 3 extension point** for future LLM semantic analysis (interface only, no external deps)

## Capabilities

### New Capabilities

- `heuristic-scoring`: Weighted anomaly detection and multi-factor risk scoring engine producing normalized 0-100 scores from independent risk factors

### Modified Capabilities

- `tool-security-analysis`: Extend the analysis pipeline to incorporate heuristic scores alongside regex findings. Tool description analysis now includes entropy, length, and structure heuristics. Finding reports include an optional `Score` field.

## Impact

- `internal/scanner/` — new `heuristic.go`, `heuristic_test.go`; modify `tool_analysis.go` to call heuristic engine
- `internal/scanner/scanner.go` — add score fields to `Result` type; add `--min-security-score` and `--max-absolute-risk` flags
- `internal/report/format.go` — display scores in table/JSON/SARIF output
- `cmd/mcp-audit/main.go` — new CI gate flags
- No external dependencies; math operations use stdlib `math`

## Non-goals

- LLM API integration — Layer 3 extension point only (interface definition)
- Machine learning models — all heuristics are deterministic rule-based
- Historical score trending — single-scan scoring only
- Real-time score streaming — scores computed at scan completion
