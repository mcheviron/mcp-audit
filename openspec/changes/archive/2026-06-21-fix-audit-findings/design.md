## Context

mcp-audit is a Go stdlib-first MCP security auditor. Audit findings span 6 packages. All fixes must stay stdlib-only, respect 500-line file limit, 70-line funlen, and 120-char lll. No new external dependencies.

## Goals / Non-Goals

**Goals:**
- Fix stdio transport so multi-step MCP protocol interactions don't hit a 5s process-lifetime kill
- Redact IPs/hostnames in upload `Finding` field
- Make SSE `SetTLS` return an error instead of silently ignoring
- Add graceful shutdown (SIGTERM/SIGINT) to proxy and daemon modes
- Add overall scan timeout to dynamic probes, surface errgroup errors
- Propagate report write errors from Fprintf calls
- Add trust config checksum verification
- Expand TLD blocklist for upload redaction
- Add configurable upstream TLS to proxy

**Non-Goals:**
- Fuzz tests, benchmarks, Windows support, real-network integration tests
- Drift detection tool rename handling
- Replacing GitHub Releases distribution mechanism

## Decisions

### 1. Stdio timeout split

**Decision**: Replace single `timeout` field in `stdioTransport` with `startupTimeout` (5s default) and rely on per-call `ctx` for request deadlines.

**Rationale**: `DefaultTimeout = 5s` was used for both startup waiting AND wrapped the entire process with `context.WithTimeout(ctx, t.timeout)` at `stdio.go:67`. The process ctx should have no deadline — only the startup check needs one. Per-request timeouts come from the caller's `ctx` parameter on `Send`.

**Implementation**: Create the exec command with `context.Background()` (no deadline). Use a short `time.After` + select for startup readiness check. Set `cmd.WaitDelay = 2 * time.Second` (Go 1.20+) so pipes close promptly on kill. Add `cmd.Cancel` for process-group kill on `Close()`.

**Alternative considered**: Keeping a configurable but long timeout (e.g., 60s). Rejected — poorly-behaved servers would still die mid-scan; better to let the caller's ctx control lifetime.

### 2. Upload Finding field redaction

**Decision**: Apply `looksLikeHost`/`looksLikeIP`/`looksLikeURL` word-by-word to `Finding` field, same as `Detail`. Expand `hostTLDs` to include `.svc`, `.cluster.local`, `.corp`, `.lan`, `.lab`, `.test`, `.internal` (general suffix).

**Rationale**: Scanner findings embed probe target IPs directly in the finding message text (e.g., `"tool %q leaked metadata via probe to %s"`). `sanitizeDetail` only touches `Detail`. The Finding text needs the same treatment.

### 3. SSE TLS error

**Decision**: `SetTLS` on SSE transport returns `fmt.Errorf("sse: TLS client certificates are not supported for SSE transport; use --transport http to force Streamable HTTP")`.

**Rationale**: Silent no-op is worse than a hard error. User thinks mTLS is active but isn't. The error message routes users to the working path. Auto-detection that falls back to SSE after HTTP failure won't trigger this — TLS is applied before transport selection.

### 4. Graceful shutdown pattern

**Decision**: Use `signal.NotifyContext` in CLI commands (`runProxy`, `runWatch`). Pass the derived context to `proxy.Start(ctx)` and `watcher.Watch(ctx)`. Proxy's `http.Server` uses `Shutdown(ctx)` with a 30s grace period. Watcher's `for` loop checks `ctx.Done()`.

**Rationale**: `signal.NotifyContext` is stdlib (Go 1.16+). No new dependencies. Clean, composable — each component gets a cancellation signal without importing `os/signal` internally.

**Alternative considered**: Dedicated signal handler goroutine with channel. Rejected — `signal.NotifyContext` is simpler and directly composable with existing context plumbing.

### 5. Overall scan timeout

**Decision**: Wrap `Probe()` errgroup in `context.WithTimeout(context.Background(), time.Duration(timeoutSecs*concurrency+30)*time.Second)`. Return `g.Wait()` error to caller instead of debug-logging.

**Rationale**: Per-probe timeouts exist but no bound on total wall-clock time. Formula `timeoutSecs * concurrency + 30` gives reasonable headroom: 10 concurrent × 30s probes = 330s max. The 30s pad accounts for handshake/setup.

**Alternative considered**: Separate `--scan-timeout` flag. Rejected — adds configuration burden. Derived timeout is predictable and sufficient.

### 6. errgroup error propagation

**Decision**: Return `g.Wait()` errors wrapped as partial results. Add a `ProbeWarnings` field to scan results or log at WARN level (not DEBUG).

**Rationale**: `slog.Debug` hides probe failures from callers. The probe function should return the first errgroup error so CLI can exit non-zero or warn. Individual probe failures are already recorded as findings; errgroup errors indicate systemic issues (concurrency bugs, resource exhaustion).

### 7. Report write error propagation

**Decision**: Check errors from all `fmt.Fprintf` calls in `writeTable`. Return first error, closing the writer if possible. `tabwriter.Flush` error already propagated — extend to the summary line and group header writes.

**Rationale**: `_, _ =` discards write errors. A broken pipe or full disk should produce a visible failure, not silent truncation.

### 8. Callback bind failure

**Decision**: `startCallbackListener` returns `(*CallbackListener, error)`. On bind failure, caller receives an error. Caller records an INFO finding: "callback listener could not bind to port X — blind SSRF detection disabled".

**Rationale**: Returning nil silently disables a security detection path. The user should know blind SSRF detection didn't run.

### 9. Trust config checksum verification

**Decision**: `trust update` downloads `trust.json.sha256` from the same release. If present, verify the SHA256 of `trust.json` against it. If missing, print a warning but proceed. The checksum file format is one line per file: `<sha256>  <filename>`.

**Rationale**: GitHub Releases compromise is a real threat (Trivy v0.69.4 precedent, March 2026). HTTPS alone doesn't prevent release tampering. A SHA256 file alongside the artifact is simple, stdlib-only (`crypto/sha256`), and backward-compatible (warn if missing).

**Alternative considered**: GPG signature verification. Rejected — key distribution complexity. Sigstore/cosign. Rejected — external dependency. SHA256 checksum is the stdlib-friendly baseline.

### 10. SSE endpoint path validation

**Decision**: Parse `serverURL + data` through `net/url.Parse`. Reject if the resulting path contains `..` segments or if the host differs from the original server URL host.

**Rationale**: Path traversal is the primary risk (CRLF injection blocked by Go 1.12+). URL parsing catches `../` sequences. Host check prevents redirect-to-different-host attacks.

### 11. Proxy upstream TLS

**Decision**: Add `--upstream-ca-cert`, `--upstream-cert`, `--upstream-key` flags to proxy command. Build a custom `http.Transport` with `TLSClientConfig` when any are set. Default transport unchanged (use `http.DefaultTransport`).

**Rationale**: Some MCP servers require mTLS or use custom CAs. The proxy currently uses `http.DefaultTransport` with no configurable TLS. The new flags are optional — zero flags = current behavior.

## Risks / Trade-offs

- **Stdio timeout split**: If a stdio server hangs forever (no ctx deadline from caller), the scan goroutine leaks. Mitigation: overall scan timeout (decision #5) bounds this.
- **SSE TLS error**: Users with auto-detected SSE + TLS config will now get errors instead of silent TLS drop. This is intentional — silent failure is worse — but could break existing scans that "worked" (without TLS).
- **Trust checksum**: If the community DB doesn't publish `.sha256` files yet, the warning is noisy. Mitigation: warn once per update, not per file.
- **Report write errors**: Checking every Fprintf adds verbosity to `writeTable`. Risk of exceeding 70-line funlen. Mitigation: extract a helper that writes and returns first error.

## Open Questions

- Should trust update checksum verification be opt-in (`--verify`) or default-on with `--no-verify` escape hatch? Default-on is safer but could surprise users if sha256 files aren't published.
