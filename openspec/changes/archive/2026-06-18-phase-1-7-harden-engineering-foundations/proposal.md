## Why

The codebase has 4 test files (zero scanner/analysis/CLI tests), silently discarded errors (`_ = g.Wait()`, `_ = io.Copy()`), no structured logging, no progress reporting, hardcoded timeouts/concurrency, no config file support, and no finding deduplication. For a security tool, these aren't polish — they're correctness and trustworthiness gaps. Users can't configure behavior without CLI flags every invocation, can't debug probe failures, and can't trust findings aren't duplicates.

## What Changes

- **Test suite**: unit tests for scanner, analysis, all CLI paths; integration test with mock MCP server via `httptest`; table-driven severity edge case tests
- **Structured logging**: replace `fmt.Fprintf(os.Stderr)` with `log/slog`; `--verbose` (DEBUG), default (INFO), `--quiet` (WARN+); `--debug` for raw request/response logging
- **Structured error types**: `ProbeError`, `ConfigError`, `TransportError` with `Unwrap()` support; retry logic for transient failures (3 retries, exponential backoff)
- **Config file**: `~/.config/mcp-audit/config.yaml` for persistent settings (format, trust-config, targets, allow/block hosts, timeout, concurrency)
- **CLI usability**: `--severity-min`, `--output-file`, `--timeout`, `--concurrency`, `--no-color` flags
- **Finding dedup**: merge findings with identical server+type+finding within a single run
- **Remediation guidance**: each severity class gets a `Remediation` field with actionable fix text
- **Progress bars**: spinner during config discovery, progress during probe phase

## Capabilities

### New Capabilities

- `logging-and-observability`: Structured logging with levels, progress reporting, and debug output
- `config-file-support`: YAML configuration file for persistent settings with CLI flag override
- `error-handling-and-retry`: Structured error types, retry logic with exponential backoff
- `finding-deduplication`: Merge duplicate findings within a scan run

### Modified Capabilities

- `report-formatting`: Add remediation guidance to findings and deduplication in output

## Impact

- `internal/scanner/` — all files gain structured logging, error wrapping, retry logic
- `internal/report/` — dedup logic, remediation text, `--output-file` support
- `main.go` — new flags, config file loading, slog initialization
- New file: `internal/configfile/` — YAML config parsing (stdlib `encoding/json` style, no yaml dep — use simple key=value or JSON for config)
- `go.mod` — no new dependencies (use JSON for config file, `log/slog` from stdlib)

## Non-Goals

- OpenTelemetry or distributed tracing
- Prometheus metrics endpoint
- External logging aggregation
- YAML library dependency — use JSON for config file format to stay zero-dep
