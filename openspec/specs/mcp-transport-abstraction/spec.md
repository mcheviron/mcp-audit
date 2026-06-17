# mcp-transport-abstraction Specification

## Purpose
Pluggable MCP transport layer supporting stdio subprocess, SSE event-stream, and Streamable HTTP with shared JSON-RPC message types and automatic transport selection.

## Requirements

### Requirement: Transport interface
The system SHALL define a `Transport` interface with `Send(ctx context.Context, method string, params any) (json.RawMessage, error)`, `SetAuthToken(token string)`, `SetAuthHeaders(headers map[string]string)`, `SetTLS(certFile, keyFile string) error`, and `Close() error`. Each transport backend SHALL implement this interface. Transports SHALL be JSON-RPC 2.0 delivery only — protocol semantics (initialize handshake, method routing) SHALL remain in the `Client` layer. The system SHALL expose a `DefaultTimeout` constant (5s) for consistent transport construction.

#### Scenario: Transport interface satisfaction
- **WHEN** a new transport backend is registered
- **THEN** it satisfies the `Transport` interface at compile time via `var _ Transport = (*httpTransport)(nil)`

#### Scenario: Send delivers JSON-RPC and returns result
- **WHEN** `Send(ctx, "tools/list", nil)` is called on any transport
- **THEN** a JSON-RPC 2.0 request is delivered to the server and the `result` field of the response is returned as `json.RawMessage`

#### Scenario: Close releases resources
- **WHEN** `Close()` is called on a transport
- **THEN** all underlying connections, subprocesses, and file descriptors are released

### Requirement: Stdio transport
The system SHALL support an stdio transport that spawns the MCP server as a subprocess using the `command` and `args` fields from `ServerEntry`. Communication SHALL use newline-delimited JSON over stdin/stdout. The transport SHALL enforce a configurable startup timeout (default 5s) via context cancellation. Transport SHALL send `SIGKILL` to the process on `Close()`.

#### Scenario: Successful stdio handshake
- **WHEN** a stdio server is spawned with valid command and args
- **THEN** the transport writes a JSON-RPC request line to stdin and reads the response line from stdout

#### Scenario: Stdio startup timeout
- **WHEN** the subprocess does not produce output within 5 seconds of startup
- **THEN** the context is cancelled and the transport returns a timeout error

#### Scenario: Stdio process cleanup
- **WHEN** `Close()` is called on a stdio transport
- **THEN** the subprocess receives SIGKILL and its stdout/stdin/stderr pipes are closed

#### Scenario: Stdio request timeout
- **WHEN** a `Send` call with a deadline context expires while waiting for response
- **THEN** the transport returns a context deadline exceeded error and the subprocess is killed and restarted on the next Send

#### Scenario: Malformed stdio output
- **WHEN** the subprocess writes non-JSON or a non-JSON-RPC response to stdout
- **THEN** the transport returns an unmarshal error

### Requirement: SSE transport
The system SHALL support SSE transport for legacy pre-2024-11-05 MCP servers. The transport SHALL connect to `<server_url>/sse` with `Accept: text/event-stream`, parse the SSE stream for an `endpoint` event containing the message endpoint URL, and POST JSON-RPC requests to that endpoint. Responses SHALL arrive via the SSE stream.

#### Scenario: SSE endpoint discovery
- **WHEN** connecting to a server that supports SSE
- **THEN** the transport GETs `/sse`, parses the `endpoint` event, and extracts the message POST URL

#### Scenario: SSE JSON-RPC round-trip
- **WHEN** a JSON-RPC request is POSTed to the discovered endpoint
- **THEN** the response arrives as an SSE `message` event on the event stream

#### Scenario: SSE connection error
- **WHEN** the `/sse` endpoint returns a non-200 status or the event stream is malformed
- **THEN** the transport returns a connection error
- **AND** the caller falls back to Streamable HTTP

#### Scenario: SSE transport timeout
- **WHEN** no SSE event is received within the configured timeout (default 10s)
- **THEN** the transport returns a timeout error

### Requirement: Streamable HTTP transport
The system SHALL support Streamable HTTP per MCP 2024-11-05 specification. The transport SHALL extract `Mcp-Session-Id` from response headers and inject it into all subsequent requests for that session. A new session SHALL be created for each probe run (no cross-run session persistence).

#### Scenario: Session ID extraction
- **WHEN** an MCP server returns `Mcp-Session-Id: abc123` in the response headers
- **THEN** the transport stores the session ID and includes `Mcp-Session-Id: abc123` in all subsequent requests

#### Scenario: No session ID
- **WHEN** an MCP server does not return a `Mcp-Session-Id` header
- **THEN** the transport operates in stateless mode with no session header on subsequent requests

#### Scenario: Session ID changed
- **WHEN** an MCP server returns a different `Mcp-Session-Id` mid-session
- **THEN** the transport updates to the new session ID

### Requirement: Transport auto-detection
The system SHALL use a unified `newTransport` factory function to construct transports from `ServerEntry` config, an optional explicit `--transport` flag override, and an `AuthConfig`. Selection priority SHALL be: explicit `--transport` flag > `ServerEntry.Transport` field > auto-detect. For auto-detected HTTP servers, the factory SHALL return an `autoTransport` that lazily tries Streamable HTTP first and falls back to SSE on the first `Send` failure (excluding auth errors).

#### Scenario: Explicit transport flag
- **WHEN** user passes `--transport stdio`
- **THEN** all servers are probed via stdio transport regardless of their config fields

#### Scenario: Config-specified transport
- **WHEN** `ServerEntry.Transport` is "http" and no `--transport` flag is set
- **THEN** the server is probed via Streamable HTTP

#### Scenario: Auto-detect stdio
- **WHEN** `ServerEntry.Command` is set, `ServerEntry.URL` is empty, and no flag overrides
- **THEN** the server is probed via stdio transport

#### Scenario: Auto-detect HTTP with SSE fallback
- **WHEN** `ServerEntry.URL` is set and Streamable HTTP fails
- **THEN** the transport layer attempts SSE as a fallback

### Requirement: Authentication support
The system SHALL support authentication via static headers, Bearer tokens, and mTLS client certificates. Auth configuration SHALL be parsed from `ServerEntry` fields (`AuthHeaders`, `AuthToken`, `TLSCertFile`, `TLSKeyFile`). Auth methods (`SetAuthToken`, `SetAuthHeaders`, `SetTLS`) SHALL be on the `Transport` interface, allowing uniform auth application to all transport types. Auth headers SHALL be injected into every HTTP and SSE request for that server.

#### Scenario: Bearer token injection
- **WHEN** `ServerEntry.AuthToken` is set to "secret123"
- **THEN** every HTTP and SSE request includes `Authorization: Bearer secret123`

#### Scenario: Custom header injection
- **WHEN** `ServerEntry.AuthHeaders` is `{"x-api-key": "key123"}`
- **THEN** every HTTP and SSE request includes `x-api-key: key123`

#### Scenario: Auth via SSE transport
- **WHEN** using SSE transport with auth configured
- **THEN** auth headers are injected into both the SSE connect GET request and the message POST request

#### Scenario: mTLS client certificate
- **WHEN** `ServerEntry.TLSCertFile` and `TLSKeyFile` point to valid PEM files
- **THEN** the HTTP client presents the certificate during TLS handshake

#### Scenario: Auth methods are no-ops on stdio
- **WHEN** using stdio transport
- **THEN** `SetAuthToken`, `SetAuthHeaders`, and `SetTLS` are no-ops (stdio uses process args, not network headers)

### Requirement: Typed auth errors
The system SHALL define an exported `ErrAuthRequired` sentinel error in the `mcp` package. HTTP and SSE transports SHALL wrap this error via `%w` when the server returns HTTP 401 or 403. The scanner layer SHALL detect auth failures using `errors.Is(err, mcp.ErrAuthRequired)` instead of string-matching error messages. Auth errors SHALL NOT trigger SSE fallback in `autoTransport`.

#### Scenario: HTTP transport wraps 401
- **WHEN** an HTTP transport receives HTTP 401 from the server
- **THEN** the returned error wraps `ErrAuthRequired`

#### Scenario: SSE transport wraps 403
- **WHEN** an SSE transport receives HTTP 403 from the message endpoint
- **THEN** the returned error wraps `ErrAuthRequired`

#### Scenario: Scanner detects auth failure
- **WHEN** `probeSingleServer` receives a handshake error
- **THEN** it checks `errors.Is(err, mcp.ErrAuthRequired)` to annotate the finding with auth guidance

#### Scenario: Auto-transport skips fallback on auth error
- **WHEN** `autoTransport.Send` fails with an auth error on HTTP
- **THEN** it does NOT fall back to SSE and returns the auth error immediately
