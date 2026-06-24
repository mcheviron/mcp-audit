## 1. Probe library

- [x] 1.1 Create `internal/scanner/probes.txt` with 150+ probe strings in pipe-delimited format (ID|category|description|text), organized by extraction/injection/role-switching/obfuscation-bypass categories
- [x] 1.2 Implement `internal/scanner/adversarial.go` with `Probe` struct, `LoadProbes() ([]Probe, error)`, and `ProbesByCategory(cat string) []Probe` using `//go:embed probes.txt`
- [x] 1.3 Write unit test in `internal/scanner/adversarial_test.go` verifying probe count, category grouping, and ID uniqueness

## 2. Deobfuscation pipeline

- [x] 2.1 Implement `deobfuscate(desc string) (string, []Finding)` in `internal/scanner/adversarial.go` with 5-stage pipeline: Unicode tag stripping, BiDi detection, zero-width scanning, Base64 decoding, TR39 confusable detection
- [x] 2.2 Create `internal/scanner/confusables.json` with TR39 subset (Cyrillic/Greek/Latin confusables for ASCII a-z/0-9), embed via `//go:embed`
- [x] 2.3 Write unit tests for each pipeline stage: Unicode tags caught, BiDi override detected, zero-width chars counted, Base64 decoded and analyzed, confusables identified

## 3. Adversarial probe execution

- [x] 3.1 Implement `RunAdversarialProbes(server Server, tools []mcp.Tool, maxProbes int) AdversarialResult` in `internal/scanner/adversarial.go`: connects via existing transport, selects up to 3 text-accepting tools, sends probes, analyzes responses
- [x] 3.2 Implement probe response analysis: extraction detection (system prompt patterns), injection detection (role-switching/instruction acceptance), and trust score computation
- [x] 3.3 Wire `--adversarial` and `--adversarial-max-probes` flags in `cmd/mcp-audit/main.go`, integrate into `runProbe` flow

## 4. Tool description analysis integration

- [x] 4.1 Modify `internal/scanner/tool_analysis.go` to run descriptions through `deobfuscate()` before existing regex checks
- [x] 4.2 Ensure deobfuscation findings (BiDi, hidden tags, etc.) are reported alongside existing regex findings in tool list inspection
- [x] 4.3 Write unit test verifying a Base64-encoded injection pattern is caught (would have been missed by raw regex)

## 5. Report output

- [x] 5.1 Add `Adversarial trust_score` field to JSON/SARIF output when `--adversarial` is used
- [x] 5.2 Add trust score column to table formatter for adversarial scan results

## 6. End-to-end tests

- [x] 6.1 Add e2e test: start MCP server that returns tool descriptions with Base64-encoded injection, run static scan, verify deobfuscation finding reported
- [x] 6.2 Add e2e test: start MCP server with BiDi-override in tool description, verify HIGH severity finding
- [x] 6.3 Add e2e test: run adversarial probes against a clean test server, verify trust score = 100
