## 1. Extend analyzeAdversarialResponse with context

- [x] 1.1 In `internal/scanner/adversarial.go`, change `analyzeAdversarialResponse` signature from `(text string) string` to `(text, probeText, toolName, toolDesc string) MatchResult` where `MatchResult` has `Indicator` and `Confidence` fields. Add constants `minConfidenceForHIGH = 0.7`, `mutatingVerbs`, `retrievalVerbs`.
- [x] 1.2 Add helper `lcsRatio(a, b string) float64` for echo detection. Add helper `classifyPurpose(toolName, toolDesc string) float64` returning purpose_factor (1.0 for mutating, 0.6 for neutral, 0.3 for retrieval).
- [x] 1.3 Update `recordAdversarialProbeResult` to pass probe text + tool description. When confidence ≥ 0.7, emit HIGH; when 0.0 < confidence < 0.7, emit INFO with low-confidence note.

## 2. Tests

- [x] 2.1 Add test cases to `internal/scanner/adversarial_test.go`: echo suppression (probe text overlaps match), retrieval-tool demotion (search/fetch/get/list), mutating-tool override (exec/delete), high-confidence extraction match (no overlap + execute tool), and threshold boundary at 0.7.
- [x] 2.2 Run `go test ./internal/scanner/...` to verify tests pass
- [x] 2.3 Run `just test-all` to verify no regression