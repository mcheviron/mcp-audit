## MODIFIED Requirements

### Requirement: Stdio transport
The system SHALL support an stdio transport that spawns the MCP server as a subprocess using the `command` and `args` fields from `ServerEntry`. Communication SHALL use newline-delimited JSON over stdin/stdout. The transport SHALL enforce a configurable startup timeout (default 5s) for the initial process spawn and readiness check. Per-request timeouts SHALL be controlled by the caller's context on `Send`, not by the process-lifetime context. Transport SHALL send `SIGKILL` to the process on `Close()`. The process command SHALL use `cmd.WaitDelay` (2s) so pipes close promptly on kill.

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

#### Scenario: Multi-step interaction survives beyond 5 seconds
- **WHEN** a stdio server takes longer than 5 seconds total across multiple `Send` calls (e.g., initialize at 2s, list tools at 4s, call tool at 7s elapsed)
- **THEN** all calls succeed because the process lifetime is not bounded by the 5s startup timeout

#### Scenario: Malformed stdio output
- **WHEN** the subprocess writes non-JSON or a non-JSON-RPC response to stdout
- **THEN** the transport returns an unmarshal error

### Requirement: Authentication support
The system SHALL support authentication via static headers, Bearer tokens, and mTLS client certificates. Auth configuration SHALL be parsed from `ServerEntry` fields (`AuthHeaders`, `AuthToken`, `TLSCertFile`, `TLSKeyFile`). Auth methods (`SetAuthToken`, `SetAuthHeaders`, `SetTLS`) SHALL be on the `Transport` interface, allowing uniform auth application to all transport types. Auth headers SHALL be injected into every HTTP and SSE request for that server. `SetTLS` on transports that do not support TLS SHALL return an error explaining the limitation instead of silently ignoring the configuration.

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

#### Scenario: SSE transport rejects TLS configuration
- **WHEN** `SetTLS(certFile, keyFile)` is called on an SSE transport
- **THEN** an error is returned indicating SSE does not support client certificates and the user should use `--transport http`

#### Scenario: Auth methods are no-ops on stdio
- **WHEN** using stdio transport
- **THEN** `SetAuthToken`, `SetAuthHeaders`, and `SetTLS` are no-ops (stdio uses process args, not network headers)

## ADDED Requirements

### Requirement: SSE endpoint path validation
The system SHALL validate the SSE endpoint path received from the `endpoint` event. The endpoint URL SHALL be parsed and its host SHALL match the original server URL host. The path SHALL not contain `..` segments. If validation fails, the transport SHALL return a connection error.

#### Scenario: Valid SSE endpoint path
- **WHEN** the SSE endpoint event contains a path `/messages` on the same host
- **THEN** the transport accepts the endpoint and uses it for message posting

#### Scenario: Path traversal in SSE endpoint
- **WHEN** the SSE endpoint event contains a path with `..` segments (e.g., `/../admin`)
- **THEN** the transport returns a connection error

#### Scenario: Different host in SSE endpoint
- **WHEN** the SSE endpoint event contains a URL with a different host than the original server URL
- **THEN** the transport returns a connection error
