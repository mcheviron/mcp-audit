## 1. Heuristic scoring engine

- [x] 1.1 Define `HeuristicScore` struct and `Scorer` type in `internal/scanner/heuristic.go` with Shannon entropy, description length, naming convention consistency, and schema complexity functions
- [x] 1.2 Implement `ScoreTools(tools []mcp.Tool) []ToolScore` computing per-tool scores from description entropy + schema complexity; each returns 0-100
- [x] 1.3 Write unit tests in `internal/scanner/heuristic_test.go` covering: empty description = 0, 100-char natural description = 100, mixed naming conventions ≤50, well-constrained schema = 100, unbounded schema ≤50

## 2. Multi-factor risk aggregation

- [x] 2.1 Implement `AggregateRisk(factors RiskFactors, weights Weights) float64` in `internal/scanner/heuristic.go` computing weighted composite score
- [x] 2.2 Implement `RiskFactors` extraction: typosquat dist from existing findings, CVE count from CVE scanner results, capability breadth from tool_analysis results, description quality from heuristic scores, network exposure from SSRF probe results
- [x] 2.3 Write unit tests for aggregation: perfect server = 100, high-risk server ≤30, weight validation (sum != 1.0 returns error)

## 3. Score integration into Result and Scanner

- [x] 3.1 Add `Score float64` and `Factors RiskFactors` fields to `scanner.Result` struct in `internal/scanner/scanner.go`
- [x] 3.2 Call heuristic engine from `runStatic`/`runProbe` after existing analysis, populate `Result.Score`
- [x] 3.3 Add `--heuristic` flag (default true) and `--score-weights` flag to scan/static/probe commands in `cmd/mcp-audit/main.go`

## 4. CI gate flags

- [x] 4.1 Add `--min-security-score` and `--max-absolute-risk` flags to scan/static commands
- [x] 4.2 After scan completes, compare each server's score against thresholds; exit code 2 on violation with message listing failing servers
- [x] 4.3 Write unit test in `cmd/mcp-audit/main_test.go` for score-based exit codes

## 5. Report format updates

- [x] 5.1 Add score column to table formatter (`internal/report/format.go`) showing composite score for each server, right-aligned
- [x] 5.2 Add `score` and `riskFactors` fields to JSON output format
- [x] 5.3 Add SARIF `rank` property mapping from score in `internal/report/sarif.go`

## 6. Layer 3 extension point

- [x] 6.1 Define `LLMAnalyzer` interface in `internal/scanner/heuristic.go`: `AnalyzeDescription(desc string) (score float64, findings []string, err error)`
- [x] 6.2 Add `--llm-endpoint` flag (placeholder, no implementation — logs "LLM analysis not yet implemented" when set with non-empty value)

## 7. End-to-end tests

- [x] 7.1 Add e2e test verifying JSON output includes `score` field with value between 0 and 100
- [x] 7.2 Add e2e test verifying `--min-security-score` flag causes non-zero exit when scores below threshold
