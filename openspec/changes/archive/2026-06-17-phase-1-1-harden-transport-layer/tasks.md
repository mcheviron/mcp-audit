## 1. Transport interface and HTTP refactor

- [x] 1.1 Define `Transport` interface in `internal/mcp/transport.go` with `Send(ctx, method, params) (json.RawMessage, error)` and `Close() error`
- [x] 1.2 Rename existing `httpClient` to `httpTransport`, make it implement `Transport`, add `Close() error` (no-op for HTTP)
- [x] 1.3 Refactor `Client` to hold a `Transport` internally, keeping `Initialize`/`ListTools`/`CallTool` methods unchanged
- [x] 1.4 Add compile-time interface satisfaction checks for all transport implementations

## 2. Stdio transport

- [x] 2.1 Create `internal/mcp/stdio.go` — `stdioTransport` struct wrapping `exec.Cmd` with stdin/stdout pipes
- [x] 2.2 Implement `Send` for stdio: write newline-delimited JSON-RPC request to stdin, read single line from stdout, unmarshal result
- [x] 2.3 Implement `Close` for stdio: kill subprocess, close pipes
- [x] 2.4 Add startup timeout via `context.WithTimeout` in `NewStdioTransport(ctx, command, args, timeout)`
- [x] 2.5 Handle request-level timeout: if context expires during `Send`, kill and restart subprocess on next call

## 3. SSE transport

- [x] 3.1 Create `internal/mcp/sse.go` — minimal SSE parser handling `event:` and `data:` fields with empty-line-delimited events
- [x] 3.2 Implement SSE transport: GET `<server_url>/sse`, discover endpoint from `endpoint` event, POST JSON-RPC to endpoint
- [x] 3.3 Handle SSE response routing: match response `id` to pending request via internal map
- [x] 3.4 Add SSE-specific timeout (default 10s) for event stream inactivity
- [x] 3.5 Implement `Close` for SSE: cancel event stream reader, close HTTP connection

## 4. Streamable HTTP upgrade

- [x] 4.1 Extract `Mcp-Session-Id` from response headers in `httpTransport.Send`
- [x] 4.2 Inject stored session ID into subsequent requests via `Mcp-Session-Id` request header
- [x] 4.3 Handle session ID rotation: update stored ID when server returns a different value

## 5. Auth support

- [x] 5.1 Add `AuthHeaders map[string]string`, `AuthToken string`, `TLSCertFile string`, `TLSKeyFile string` to `config.ServerEntry`
- [x] 5.2 Parse auth fields from MCP config JSON in `parseMcpServers` (headers, token, tls config sections)
- [x] 5.3 Wire auth into HTTP transport: inject `AuthHeaders` into requests, set `Authorization: Bearer` from token
- [x] 5.4 Implement mTLS: configure `tls.Config` with client cert when `TLSCertFile` and `TLSKeyFile` are set
- [x] 5.5 Add `--auth-token`, `--auth-header`, `--tls-cert`, `--tls-key` CLI flags in `main.go`
- [x] 5.6 Report INFO finding when server returns 401/403 and no auth is configured

## 6. Transport auto-detection and probe wiring

- [x] 6.1 Add `--transport` flag (values: `stdio`, `sse`, `http`, empty=auto) to CLI
- [x] 6.2 Implement `selectTransport(entry config.ServerEntry, flag string) Transport` in `internal/scanner/dynamic.go`
- [x] 6.3 Replace `collectHTTPServers()` with `collectServers()` that returns all servers regardless of transport
- [x] 6.4 Wire transport selection into `runMCPProbes`: create transport per server, pass to MCP client, close on completion
- [x] 6.5 Add SSE-to-HTTP fallback: if Streamable HTTP `initialize` fails, retry with SSE transport

## 7. Tests

- [x] 7.1 Test stdio transport with mock subprocess (echo JSON-RPC responses via shell script fixture)
- [x] 7.2 Test SSE transport with `httptest.Server` serving `text/event-stream`
- [x] 7.3 Test Streamable HTTP session ID extraction and injection
- [x] 7.4 Test transport auto-detection: command → stdio, url → http, http-fail → sse-fallback
- [x] 7.5 Test auth header injection and mTLS configuration
- [x] 7.6 Test stdio timeout and process cleanup on context cancellation
