## 1. Implement chain grouping by server sequence

- [x] 1.1 In `internal/analysis/chains.go`, add a helper `serverSequence(path)` that extracts server names from a tool-level chain path and joins them with ` -> `. Modify `detectCompositionChains` to collect all raw paths first, then group by server sequence, then emit one finding per group with max severity, server-sequence description with path count, and up to 3 example tool-level paths in the detail field.
- [x] 1.2 Run `just check` to verify no lint issues

## 2. Tests

- [x] 2.1 Add test cases to `internal/analysis/analysis_test.go`: single path per sequence (no grouping needed), multiple tool paths mapping to same server sequence (grouped into one finding), mixed-length chains in same group (max severity), and server sequence with >3 tool-level paths (detail shows exactly 3 examples)
- [x] 2.2 Run `go test ./internal/analysis/...` to verify tests pass
- [x] 2.3 Run `just test-all` to verify no regression
