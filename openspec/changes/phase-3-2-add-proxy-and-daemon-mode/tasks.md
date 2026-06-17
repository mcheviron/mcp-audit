## 1. Daemon mode

- [ ] 1.1 Create `internal/daemon/watcher.go` — fsnotify on config file directories
- [ ] 1.2 Implement debounced re-scan on filesystem events (500ms window)
- [ ] 1.3 Implement periodic re-scan at configurable interval (`--watch-interval`, default 5m)
- [ ] 1.4 Add `--on-finding` flag: execute shell command with finding summary on new findings
- [ ] 1.5 Add `mcp-audit watch` subcommand with `--watch-interval`, `--on-finding` flags

## 2. Proxy mode

- [ ] 2.1 Create `internal/proxy/proxy.go` — `httputil.ReverseProxy` with custom Director to target
- [ ] 2.2 Create `internal/proxy/inspector.go` — intercept JSON-RPC responses, run analysis pipeline
- [ ] 2.3 Implement `--block-critical`: return MCP error response instead of forwarding
- [ ] 2.4 Add `mcp-audit proxy` subcommand with `--listen`, `--target`, `--block-critical` flags
- [ ] 2.5 Log all JSON-RPC methods and response times to stderr

## 3. MCP client callbacks

- [ ] 3.1 Add `OnRequest func(method string, params any)` and `OnResponse func(method string, result json.RawMessage, duration time.Duration)` fields to `mcp.Client`
- [ ] 3.2 Invoke callbacks in `httpClient.call()` before send and after response unmarshal
- [ ] 3.3 Wire proxy inspector through these callbacks

## 4. Tests

- [ ] 4.1 Test daemon watcher detects file changes (touch config file, verify re-scan)
- [ ] 4.2 Test daemon debounce: rapid writes produce single re-scan
- [ ] 4.3 Test proxy forwards and inspects tools/list and tools/call traffic
- [ ] 4.4 Test proxy blocking mode returns MCP error for CRITICAL finding
- [ ] 4.5 Test client callbacks invoked for request and response
