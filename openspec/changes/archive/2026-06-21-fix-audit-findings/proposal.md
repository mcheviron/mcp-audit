## Why

A thorough audit identified 12 concrete issues across 6 subsystems — including a functional breakage in stdio transport (P0), an internal IP leak in community uploads (P1), and missing graceful shutdown (P1). These must be fixed before the tool is production-hardened for security-critical or multi-tenant deployments.

## What Changes

- Stdio transport: separate startup timeout from per-request timeout so multi-step protocols survive the full probe pipeline
- Community uploads: redact IPs and hostnames in the `Finding` field (currently only `Detail` is sanitized), expand TLD blocklist with k8s/corp/cloud suffixes
- SSE transport: reject `SetTLS` calls instead of silently ignoring them; validate endpoint path
- Graceful shutdown: add `os/signal` handling to proxy and daemon modes with `http.Server.Shutdown`
- Dynamic probes: wrap errgroup in an overall timeout context, surface errgroup errors instead of debug-logging them
- Report output: propagate write errors from all `Fprintf` calls in table format
- Callback listener: report bind failure as a finding instead of silently returning nil
- Trust config update: verify a SHA256 checksum file alongside `trust.json` from GitHub releases
- Proxy mode: add configurable upstream TLS (mTLS, cert pinning)

## Capabilities

### New Capabilities

None — all fixes fall under existing capability umbrellas.

### Modified Capabilities

- `mcp-transport-abstraction`: stdio timeout semantics change (startup vs per-request), SSE `SetTLS` returns error, SSE endpoint path validated
- `community-intelligence`: upload finding field redaction, expanded TLD list, trust config checksum verification
- `dynamic-ssrf-probing`: overall scan timeout, errgroup error propagation, callback bind failure detection
- `report-formatting`: table writer propagates I/O errors from all write calls
- `proxy-mode`: graceful shutdown on SIGTERM/SIGINT, configurable upstream TLS transport
- `daemon-mode`: graceful shutdown on SIGTERM/SIGINT via cancellation context

## Non-goals

- Adding fuzz tests, benchmarks, or Windows support (separate effort)
- Real-network integration tests (separate effort)
- Drift detection tool rename handling (separate effort)
- Replacing GitHub Releases with a different distribution mechanism

## Impact

- `internal/mcp/stdio.go` — split timeout, add `RequestTimeout` field
- `internal/mcp/sse.go` — `SetTLS` return error, endpoint path validation
- `internal/mcp/transport.go` — add `RequestTimeout` to interface or transport structs
- `cmd/mcp-audit/main_upload.go` — sanitize `Finding` field, expand `hostTLDs`
- `cmd/mcp-audit/main_trust.go` — add checksum download and verification step
- `internal/scanner/dynamic.go` — overall timeout context, errgroup error handling
- `internal/scanner/callback.go` — return error on bind failure, caller handles
- `internal/report/format.go` — return errors from Fprintf calls
- `internal/proxy/proxy.go` — `Shutdown()`, configurable TLS, signal handling
- `internal/daemon/watcher.go` — cancellation context, signal handling
- `cmd/mcp-audit/proxy_cmd.go` — wire up signal handling
- `cmd/mcp-audit/watch.go` — wire up signal handling
