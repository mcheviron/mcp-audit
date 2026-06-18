## Context

Engineering gaps: 4 test files, silently discarded errors, no structured logging, no config file, hardcoded timeouts/concurrency, no progress bars, no finding dedup, no remediation guidance.

## Goals / Non-Goals

**Goals:** Test suite (scanner, analysis, CLI, integration), slog logging with levels, structured error types with retry, JSON config file, CLI usability flags, finding dedup, remediation text, progress bars.

**Non-Goals:** OpenTelemetry, Prometheus, external log aggregation, YAML dependency.

## Decisions

### slog over custom logger

stdlib `log/slog` (Go 1.21+) provides levels, structured key-value pairs, and handler customization. `--verbose` sets slog level to DEBUG, `--quiet` to WARN. `--debug` adds source file location. No external dependency.

### Config file: JSON at `~/.config/mcp-audit/config.json`

All CLI flags have a JSON counterpart. CLI flags override config file values. Example:
```json
{"format": "json", "trust_config": "~/trust.json", "timeout": 10, "concurrency": 5}
```
JSON chosen over YAML to avoid external parser dependency.

### Error types: sentinel errors + wrapping

```go
var ErrProbeTimeout = errors.New("probe timeout")
var ErrConfigParse = errors.New("config parse error")
type ProbeError struct { Target, Server string; Err error }
func (e *ProbeError) Unwrap() error { return e.Err }
```

### Retry: 3 attempts, exponential backoff

Only for transient errors (timeout, connection refused, 503). Start at 100ms, double each attempt. Max 3 attempts. Context cancellation stops retry.

### Finding dedup: map key on server+type+normalized finding

Hash the (Server, Type, Finding) tuple. When two findings produce same hash, keep the highest-severity one with combined detail. Dedup runs after all probes complete, before report output.

### Progress bars: simple spinner to stderr

`\r⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏` cycling every 100ms during probe phase. Show "Probing N servers..." with spinner. On completion, clear line and print summary. No external progress bar library.
