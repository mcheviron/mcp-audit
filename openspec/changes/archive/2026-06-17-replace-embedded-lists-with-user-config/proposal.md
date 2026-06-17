## Why

Embedded `known_legitimate.txt` (25 entries) and `known_malicious.txt` (13 entries) are compiled into the binary. This doesn't scale — the MCP ecosystem has hundreds of servers, typosquat variants are infinite, and the lists rot immediately. For a real product, users need to define their own trust boundaries per organization, not inherit a hardcoded snapshot that's wrong the day after release.

## What Changes

- **BREAKING**: Remove `known_legitimate.txt`, `known_malicious.txt`, `typosquat.go`, and the `//go:embed` directives
- Add `--trust-config <path>` flag pointing to a JSON file with user-defined `trusted` and `blocked` package lists
- Search for `~/.config/mcp-audit/trust.json` as default when `--trust-config` is omitted
- If no config file exists, skip typosquat checks silently (no embedded lists, no false positives)
- Explicit `--trust-config` path that fails to load exits with code 2
- When config is loaded: exact match on `blocked` → CRITICAL; exact match on `trusted` → PASS; Levenshtein distance ≤2 from `trusted` → INFO
- Support per-tool (`tools`) and per-server (`servers`) scope overrides in trust config JSON
- Introduce `Scanner` struct holding `TrustConfig`, probe targets, allow/block hosts
- Integrate trust config into both static (`Static`) and dynamic (`Probe`) pipelines

## Capabilities

### New Capabilities

<!-- None — all work falls under existing umbrella -->

### Modified Capabilities

- `typosquat-detection`: Replace compile-time embedded lists with user-supplied `--trust-config` JSON file. Remove `//go:embed` mechanism. Add per-tool and per-server trust scoping. Add `Scanner` struct for shared scanner configuration. Integrate trust filtering into dynamic probe pipeline.

## Impact

- `internal/scanner/typosquat.go` — deleted
- `internal/scanner/known_legitimate.txt` — deleted
- `internal/scanner/known_malicious.txt` — deleted
- `internal/scanner/trust.go` — deleted (moved to config)
- `internal/config/trust.go` — new: `TrustConfig` with embedded `TrustScope`, `LoadTrust`, `DefaultTrustPath`, `ScopeFor`
- `internal/scanner/scanner.go` — new: `Scanner` struct, `NewScanner`, `SetTrustConfig`
- `internal/scanner/static.go` — `Scanner.Static()`, `checkTyposquat` with scoped trust resolution
- `internal/scanner/dynamic.go` — `Scanner.Probe()` with trust-based server filtering, `DynamicConfig` removed
- `internal/scanner/analysis.go` — new: extracted probe response analysis functions
- `main.go` — new `--trust-config` flag, `flags` struct replaces multi-return `parseFlags`
