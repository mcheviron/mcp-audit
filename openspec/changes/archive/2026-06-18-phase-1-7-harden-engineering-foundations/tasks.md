## 1. Structured logging

- [x] 1.1 Initialize `slog.Logger` in `main()` with level based on `--verbose`/`--quiet` flags
- [x] 1.2 Replace all `fmt.Fprintf(os.Stderr, ...)` calls with `slog.Info/Warn/Error/Debug`
- [x] 1.3 Add `--debug` flag enabling source file location in log handler
- [x] 1.4 Pass logger through context or Scanner struct to scanner/report packages

## 2. Progress reporting

- [x] 2.1 Implement spinner in `main.go` cycling every 100ms during discovery and probe phases
- [x] 2.2 Show "Discovering configs..." then "Probing N servers..." status lines
- [x] 2.3 Clear spinner line on completion before printing summary

## 3. Config file support

- [x] 3.1 Create `internal/configfile/config.go` with JSON config loading from `~/.config/mcp-audit/config.json`
- [x] 3.2 Merge config file values as defaults, CLI flags as overrides
- [x] 3.3 Support all CLI flags as config file keys

## 4. Structured error types

- [x] 4.1 Define `ProbeError`, `ConfigError`, `TransportError` in `internal/scanner/errors.go`
- [x] 4.2 Implement `Error()` and `Unwrap()` on each type
- [x] 4.3 Replace all `fmt.Errorf` with typed errors throughout codebase
- [x] 4.4 Eliminate all bare `_` error discards — check or log every error

## 5. Retry logic

- [x] 5.1 Implement `retry(ctx, maxAttempts int, fn func() error) error` in `internal/scanner/retry.go`
- [x] 5.2 Classify errors as transient (timeout, connection refused, 503) vs permanent (400, 401, 404)
- [x] 5.3 Wrap probe calls in retry for transient failures only

## 6. Finding deduplication

- [x] 6.1 Implement `deduplicateFindings(results []Result) []Result` in `internal/report/dedup.go`
- [x] 6.2 Normalize finding text: lowercase, collapse whitespace
- [x] 6.3 Merge duplicates keeping highest severity and unique detail fields
- [x] 6.4 Call dedup before report output in `writeResults`

## 7. Remediation guidance

- [x] 7.1 Add `Remediation string` field to `scanner.Result`
- [x] 7.2 Populate remediation text per severity class and finding type
- [x] 7.3 Display remediation in table (when non-empty), JSON, and SARIF output

## 8. CLI usability flags

- [x] 8.1 Add `--severity-min` flag filtering output to minimum severity level
- [x] 8.2 Add `--output-file` flag writing report to file instead of stdout
- [x] 8.3 Add `--timeout` and `--concurrency` flags (previously hardcoded)
- [x] 8.4 Add `--no-color` flag disabling terminal color codes

## 9. Tests

- [x] 9.1 Test slog level filtering at each verbosity
- [x] 9.2 Test config file loading, CLI override, and missing file behavior
- [x] 9.3 Test ProbeError/ConfigError/TransportError wrapping and unwrapping
- [x] 9.4 Test retry logic: transient success after 2 retries, permanent failure after 1, context cancellation
- [x] 9.5 Test dedup: identical findings merged, different findings preserved, severity escalation
- [x] 9.6 Test remediation text populated for each severity class
- [x] 9.7 Test `--severity-min`, `--output-file`, `--timeout`, `--concurrency`, `--no-color`
- [x] 9.8 Integration test: full scan pipeline with mock MCP server via httptest
