## Why

Initial `build-mcp-auditor` implementation shipped working behavior but left 5 architectural shortcuts: dead struct fields, sequential I/O where concurrency fits, no interface for MCP transport, hardcoded parser dispatch, and hardcoded probe targets. These are correctness-neutral but compound as debt — each new tool, target, or test must work around them.

## What Changes

- **Remove or wire dead fields**: `ConfigPath` in `ServerEntry` set but never read; `AllowHosts`/`BlockHosts` in `DynamicConfig` spec'd but unimplemented. Wire the latter into probe filtering; surface `ConfigPath` in reports.
- **Parallelize direct HTTP probes**: `runDirectProbes` loops sequentially over servers × targets. Use `errgroup` with limit for concurrent probing.
- **Define MCP transport interface**: `mcp.Client` is a concrete struct. Extract `Transporter` interface so tests and callers don't couple to the HTTP implementation.
- **Parser registry for discover+parser**: `config.Discover()` hardcodes a linear sequence of parser calls. Replace with a registry of `(name, paths, parser)` entries so adding a tool is one line.
- **Configurable probe targets**: `probeTargets` is a package-level `var`. Accept `--targets` flag (comma-separated URLs) with the built-in list as default.

## Capabilities

### New Capabilities

- `concurrent-direct-probes`: Parallel HTTP probe execution with bounded concurrency via errgroup.
- `mcp-transport-interface`: `Transporter` interface decoupling MCP protocol from HTTP transport.
- `parser-registry`: Registry-based tool discovery replacing hardcoded parser dispatch.
- `configurable-probe-targets`: `--targets` flag to override built-in probe target list.

### Modified Capabilities

- `dynamic-ssrf-probing`: Implement allowlist/blocklist filtering currently in spec but not wired; add `--targets` flag.

## Impact

- `internal/scanner/dynamic.go` — parallel probe loop, target config, allowlist/blocklist wiring
- `internal/mcp/transport.go` — extract interface
- `internal/mcp/transport_test.go` — test against interface
- `internal/config/discover.go` — registry pattern
- `internal/report/format.go` — surface ConfigPath in output
- `main.go` — new `--targets`, `--allow-hosts`, `--block-hosts` flags
