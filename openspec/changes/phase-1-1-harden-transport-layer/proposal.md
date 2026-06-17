## Why

The MCP client currently only speaks plain HTTP POST. Over 60% of real-world MCP servers use stdio transport (subprocess-based), and many legacy servers only support SSE. The tool discovers stdio servers during config scanning but silently skips them during dynamic probing — leaving the majority of a user's MCP attack surface completely unexamined. Additionally, the HTTP implementation lacks Streamable HTTP session management and authentication support, meaning servers requiring OAuth or API keys cannot be probed at all.

## What Changes

- Implement stdio transport: spawn MCP server subprocesses, communicate over stdin/stdout JSON-RPC, enforce per-process timeouts
- Implement SSE transport for legacy pre-2024-11-05 servers with `/sse` endpoint discovery and event-stream parsing
- Upgrade HTTP transport to Streamable HTTP per MCP 2024-11-05 spec with `Mcp-Session-Id` header management and session reuse
- Add authentication support: API key headers, OAuth 2.0 Bearer tokens, and mTLS client certificates — all configurable via trust config or CLI flags
- Detect transport type at probe time rather than assuming HTTP for all reachable servers
- Add per-transport timeout configuration with sensible defaults (5s stdio startup, 10s SSE connect, 5s HTTP)

## Capabilities

### New Capabilities

- `mcp-transport-abstraction`: Pluggable MCP transport layer supporting stdio subprocess, SSE event-stream, and Streamable HTTP with shared JSON-RPC message types. Transport selection is automatic based on server config or explicit via CLI flag.

### Modified Capabilities

- `dynamic-ssrf-probing`: Extend MCP handshake and probe pipeline to support stdio and SSE transports in addition to the existing HTTP transport. SSRF probe payloads are identical across transports but delivery mechanism adapts per transport.

## Impact

- `internal/mcp/` — new `transport.go` (Transport interface), `stdio.go`, `sse.go`, `session.go`; existing `transport.go` renamed to `http.go`
- `internal/scanner/dynamic.go` — transport selection logic, stdio/SSE server collection alongside HTTP servers
- `internal/config/types.go` — `ServerEntry` gains `AuthHeaders`, `AuthToken`, `TLSCertFile`, `TLSKeyFile` fields
- `internal/config/parser.go` — parse auth-related fields from MCP config JSON
- `internal/config/trust.go` — `TrustConfig` gains optional auth credential sections
- `main.go` — new `--auth-header`, `--auth-token`, `--tls-cert`, `--tls-key`, `--transport` flags
- `go.mod` — no new dependencies (stdlib `os/exec` for stdio, stdlib `net/http` for SSE/Streamable HTTP)

## Non-Goals

- WebSocket transport (not specified in any MCP protocol version)
- Automatic OAuth token refresh or OAuth flow orchestration — only static token/header injection
- Stdio server lifecycle management (health checks, auto-restart) — audit tool launches transient processes, doesn't manage long-running servers
- Transport-level fuzzing (separate proposal)
- gRPC or Unix socket transport (no MCP spec for these yet)
