## 1. Finding cross-reference infrastructure

- [x] 1.1 Add `RelatedFindings []FindingRef` field to `scanner.Result` struct in `internal/scanner/scanner.go` with ID, type, and label fields
- [x] 1.2 Implement `LinkFindings(results []Result)` in `internal/scanner/blast_radius.go` that populates `RelatedFindings` by matching server names across CVE, credential, and tool analysis results
- [x] 1.3 Write unit test in `internal/scanner/blast_radius_test.go` verifying CVE links to credential finding on same server

## 2. Blast-radius chain computation

- [x] 2.1 Implement `ComputeChains(results []Result, depth int) []Chain` in `internal/scanner/blast_radius.go` performing BFS from each CVE finding through package->server->config->tool->credential edges
- [x] 2.2 Define `ChainHop` struct with type, id, label, severity fields and `Chain` struct with hops, max_severity, truncated flag
- [x] 2.3 Write unit tests: 3-hop chain, depth truncation at 2, no CVEs produces empty chains, chain max_severity computed correctly

## 3. Compliance mapping engine

- [x] 3.1 Create `internal/scanner/compliance/` directory with 5 embedded JSON mapping files (soc2.json, nist-ai-rmf.json, owasp-llm.json, mitre-atlas.json, eu-ai-act.json)
- [x] 3.2 Implement `internal/scanner/compliance.go` with `LoadMappings()`, `MapToCompliance(findingType, severity) []Control`, and `FilterByFramework(findings, framework) []Result`
- [x] 3.3 Write unit tests for mapping correctness: credential finding -> SOC 2 CC6.1, injection finding -> OWASP LLM01, unknown type -> empty mapping

## 4. Evidence export

- [x] 4.1 Implement `ExportEvidence(path, key string, results []Result, chains []Chain) error` in `internal/report/evidence.go` producing signed JSON bundle with HMAC-SHA256 chain
- [x] 4.2 Implement HMAC chain: per-entry hash = HMAC(key, id || data || prev_hash), chain_valid flag computed on write
- [x] 4.3 Write unit test verifying HMAC chain integrity (recompute with same key passes, different key fails)

## 5. CLI flags and output integration

- [x] 5.1 Add `--blast-radius`, `--blast-radius-depth`, `--compliance-framework`, `--export-evidence`, `--evidence-key` flags to scan/static commands in `cmd/mcp-audit/main.go`
- [x] 5.2 Integrate chain computation, compliance mapping, and evidence export into the scan pipeline (after all scanning phases complete)
- [x] 5.3 Update SARIF output to include `relatedFindings` and `complianceTags`; update JSON output format; add compliance summary section to table output

## 6. End-to-end tests

- [x] 6.1 Add e2e test: scan with mock CVE + credential findings on same server, verify `related_findings` populated in JSON output
- [x] 6.2 Add e2e test: scan with `--blast-radius`, verify chain output has correct hop types
- [x] 6.3 Add e2e test: scan with `--compliance-framework owasp-llm`, verify output filtered to OWASP-mapped findings
- [x] 6.4 Add e2e test: scan with `--export-evidence`, verify file written and HMAC chain valid
