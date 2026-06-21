## 1. Stdio transport timeout split (P0)

- [x] 1.1 Add `startupTimeout` field to `stdioTransport`, rename existing `timeout` — separate process lifetime from startup deadline (`internal/mcp/stdio.go`, `internal/mcp/transport.go`)
- [x] 1.2 Create exec command with `context.Background()`; use short `time.After` + select for startup readiness check instead of wrapping entire process context (`internal/mcp/stdio.go`)
- [x] 1.3 Set `cmd.WaitDelay = 2 * time.Second` so pipes close promptly on kill, update `kill()` to handle `WaitDelay` (`internal/mcp/stdio.go`)
- [x] 1.4 Update `TestStdioTransportRestart` and `TestStdioTransport` to verify multi-step interactions survive beyond 5s (`internal/mcp/transport_test.go`)

## 2. Upload Finding field redaction (P1)

- [x] 2.1 Run `sanitizeDetail` logic (word-by-word host/IP/URL check) on `r.Finding` in `anonymizeFindings` (`cmd/mcp-audit/main_upload.go`)
- [x] 2.2 Expand `hostTLDs` to include `.svc`, `.cluster.local`, `.corp`, `.lan`, `.lab`, `.test`, `.localhost`; add generic `.internal` suffix (not just `.compute.internal`) (`cmd/mcp-audit/main_upload.go`)
- [x] 2.3 Add test cases for Finding field redaction and new TLD suffixes (`cmd/mcp-audit/main_upload_test.go`)

## 3. Graceful shutdown for proxy and daemon (P1)

- [x] 3.1 Add `signal.NotifyContext` in `runProxy`, pass derived ctx to `proxy.Start(ctx)`, add `Shutdown(context.Context) error` to proxy calling `srv.Shutdown` (`cmd/mcp-audit/proxy_cmd.go`, `internal/proxy/proxy.go`)
- [x] 3.2 Add `signal.NotifyContext` in `runWatch`, pass derived ctx to `watcher.Watch(ctx)`, add `ctx.Done()` check in watch loop with ticker cleanup (`cmd/mcp-audit/watch.go`, `internal/daemon/watcher.go`)

## 4. Dynamic probe hardening (P2)

- [x] 4.1 Wrap `Probe()` errgroup in `context.WithTimeout` computed from `timeoutSecs * concurrency + 30s`; return timeout error alongside partial results (`internal/scanner/dynamic.go`)
- [x] 4.2 Return `g.Wait()` errors from `runDirectProbes` and `runMCPProbes` instead of `slog.Debug`; bubble up through `Probe()` (`internal/scanner/dynamic.go`)
- [x] 4.3 Change `startCallbackListener` to return `(*CallbackListener, error)`; record INFO finding on bind failure instead of silently returning nil (`internal/scanner/callback.go`, `internal/scanner/dynamic.go`)

## 5. SSE transport fixes (P2)

- [x] 5.1 Make `SetTLS` on SSE transport return an error with guidance to use `--transport http` (`internal/mcp/sse.go`)
- [x] 5.2 Parse SSE endpoint URL through `net/url.Parse`, validate host matches original server URL host, reject paths with `..` segments (`internal/mcp/sse.go`)

## 6. Trust config checksum verification (P2)

- [x] 6.1 Download `trust.json.sha256` alongside `trust.json` in `runTrustUpdate`, verify SHA256 before writing; abort on mismatch, warn if checksum file absent (`cmd/mcp-audit/main_trust.go`)
- [x] 6.2 Add test for checksum verification and missing-checksum-file fallback (`cmd/mcp-audit/main_trust_test.go`)

## 7. Report write error propagation (P3)

- [x] 7.1 Check errors from summary and group-header `fmt.Fprintf` calls in `writeTable`; return first error, early-exit (`internal/report/format.go`)

## 8. Proxy upstream TLS (P3)

- [x] 8.1 Add `--upstream-ca-cert`, `--upstream-cert`, `--upstream-key` flags to proxy command; build custom `http.Transport` with `TLSClientConfig` when any are set (`cmd/mcp-audit/proxy_cmd.go`, `internal/proxy/proxy.go`)

## 9. Verification

- [x] 9.1 Run `just check` (fmt → fix → tidy → vet → build → test → loc-check → lint) — zero issues
- [x] 9.2 Run `go test ./... -count=1` — all existing tests pass with no regressions
