## Context

`internal/mcp/transport.go` currently has a single concrete implementation: HTTP POST to a URL. The `Client` interface has three methods (`Initialize`, `ListTools`, `CallTool`) but the constructor `NewClient` only returns an `httpClient`. Stdio servers discovered in config scanning (comprising ~60% of real-world MCP servers) are silently skipped during dynamic probing because `collectHTTPServers()` in `dynamic.go` filters to `Transport == "http"`. SSE servers (legacy pre-2024-11-05) have no transport at all. The MCP 2024-11-05 spec requires Streamable HTTP with `Mcp-Session-Id` header management — current implementation sends plain POST with no session tracking. Authentication (OAuth tokens, API keys, mTLS) is entirely absent.

## Goals / Non-Goals

**Goals:**
- Pluggable `Transport` interface supporting stdio, SSE, and Streamable HTTP backends
- Automatic transport selection from `ServerEntry` config (command+args → stdio, url → HTTP/SSE)
- Stdio: spawn subprocess, communicate over stdin/stdout with newline-delimited JSON-RPC
- SSE: discover `/sse` endpoint, parse `text/event-stream`, handle reconnection
- Streamable HTTP: `Mcp-Session-Id` header propagation, session lifecycle
- Authentication: static header injection (`Authorization: Bearer`, `x-api-key`), mTLS client certs from file
- Probe all transports during dynamic phase, not just HTTP
- No new external dependencies — `os/exec`, `net/http`, `bufio` from stdlib

**Non-Goals:**
- OAuth flow orchestration (token refresh, PKCE) — only static token/header injection
- WebSocket transport (not specified by MCP)
- Stdio server lifecycle management (health checks, auto-restart) — probe-only, transient processes
- Stdio transport for Windows (focus macOS/Linux; Windows has different subprocess semantics)
- gRPC or Unix socket transport

## Decisions

### Transport interface: single `Transport` interface with `Send(ctx, method, params) (result, error)`

Rather than exposing transport-specific details, the Transport interface mirrors the existing `Client` pattern but at the connection level. `Initialize`, `ListTools`, `CallTool` remain on `Client` which holds a `Transport` internally. This keeps the probe layer unchanged.

```go
type Transport interface {
    Send(ctx context.Context, method string, params any) (json.RawMessage, error)
    Close() error
}
```

Alternative: make Transport implement the full Client interface. Rejected — `Client` has MCP-semantic methods (Initialize with protocol version negotiation) while Transport is purely JSON-RPC delivery. Separation keeps transport implementations minimal.

### Stdio transport: subprocess with line-delimited JSON

Spawn the command + args from `ServerEntry`, write JSON-RPC request as single line to stdin, read single line from stdout. Enforce 5s startup timeout via `context.WithTimeout` on the first Send. Kill process on `Close()`.

Alternative: use `bufio.Scanner` for line reading. Accepted — simplest approach for newline-delimited protocol.

### SSE transport: GET /sse with `Accept: text/event-stream`

Connect to `<server_url>/sse`, parse SSE events for `endpoint` event containing the message endpoint URL, then POST JSON-RPC to that endpoint. Response comes back via the SSE stream. This is the legacy pre-2024-11-05 pattern.

Alternative: skip SSE entirely. Rejected — many production MCP servers still use SSE, especially older ones. Coverage gap is too large.

### Streamable HTTP: session-aware wrapper

Wrap the existing HTTP transport with `Mcp-Session-Id` extraction from response headers and injection into subsequent requests. Session persists for probe lifetime only (one-shot audit, not long-lived client).

### Auth: field injection, not negotiation

Parse `ServerEntry.AuthHeaders` (map[string]string) and inject into every request. Parse `ServerEntry.AuthToken` as shorthand for `Authorization: Bearer <token>`. mTLS via `ServerEntry.TLSCertFile`/`TLSKeyFile` → `tls.Config` on the HTTP client. No OAuth flow — static only.

### Transport auto-detection

Priority: explicit `--transport` flag > `ServerEntry.Transport` field > auto-detect. Auto-detect: if `Command` is set → stdio; if `URL` is set → try Streamable HTTP first, fall back to SSE on failure.

## Risks / Trade-offs

- **Stdio subprocess lifecycle** → Probe runs are short-lived (30s timeout), but zombie processes possible if probe panics. Mitigation: `defer transport.Close()` with `Process.Kill()` in all code paths. Context cancellation propagates to `exec.CommandContext`.
- **SSE parsing complexity** → SSE is a streaming protocol; the stdlib has no SSE parser. Mitigation: implement minimal SSE parser (~50 lines) handling only `data:`, `event:`, and empty-line-delimited events. Don't parse comments or multi-line fields.
- **Session ID leak across probes** → Sessions should be per-server, not shared. Mitigation: each `Transport` instance owns its session. No global session store.
- **Auth credentials in CLI flags** → `--auth-token` on command line is visible in `ps`. Mitigation: document this risk; recommend trust config file for persistent credentials. Accept `--auth-token @-` to read from stdin.

## Open Questions

- Should stdio transport support env vars from config? (e.g., `"env": {"NODE_ENV": "production"}` in MCP config JSON)
- How to handle servers that require `notifications/initialized` before accepting tool calls? Current client sends `initialize` but doesn't send the notification.
