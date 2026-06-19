## 1. Daemon mode

- [x] 1.1 Create `internal/daemon/watcher.go` — polling-based config file watching
- [x] 1.2 Implement debounced re-scan on filesystem events (500ms window)
- [x] 1.3 Implement periodic re-scan at configurable interval (`--watch-interval`, default 5m)
- [x] 1.4 Add `--on-finding` flag: execute shell command with finding summary on new findings
- [x] 1.5 Add `mcp-audit watch` subcommand with `--watch-interval`, `--on-finding` flags

## 2. Proxy mode

- [x] 2.1 Create `internal/proxy/proxy.go` — `httputil.ReverseProxy` with custom Director to target
- [x] 2.2 Create `internal/proxy/inspector.go` — intercept JSON-RPC responses, run analysis pipeline
- [x] 2.3 Implement `--block-critical`: return MCP error response instead of forwarding
- [x] 2.4 Add `mcp-audit proxy` subcommand with `--listen`, `--target`, `--block-critical` flags
- [x] 2.5 Log all JSON-RPC methods and response times to stderr

## 3. MCP client callbacks

- [x] 3.1 Add `OnRequest func(method string, params any)` and `OnResponse func(method string, result json.RawMessage, duration time.Duration)` fields as `CallbackHooks` on transport
- [x] 3.2 Invoke callbacks in `HTTPTransport.Send()` before send and after response unmarshal
- [x] 3.3 Callbacks available on all transport types (HTTPTransport, sseTransport, autoTransport, stdioTransport)

## 4. Tests

- [x] 4.1 Test daemon watcher debounce behavior (rapid events produce single scan)
- [x] 4.2 Test daemon diffFindings detects new findings correctly
- [x] 4.3 Test proxy inspects tools/list (prompt injection in descriptions) and tools/call (SSRF, credentials)
- [x] 4.4 Test proxy blocking mode returns MCP error for CRITICAL finding
- [x] 4.5 Test client callbacks invoked for request and response
