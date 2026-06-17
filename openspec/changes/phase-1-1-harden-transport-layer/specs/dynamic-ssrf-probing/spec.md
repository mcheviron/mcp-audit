# dynamic-ssrf-probing Delta Specification

## ADDED Requirements

### Requirement: Transport-aware server collection
The system SHALL collect all discoverable MCP servers for dynamic probing regardless of transport type. Servers with `Command` set (stdio) and servers with `URL` set (HTTP/SSE) SHALL both be included in the probe pipeline.

#### Scenario: Stdio server included in probe
- **WHEN** a discovered config contains a server with `command: "npx"` and `args: ["-y", "@scope/mcp-server"]`
- **THEN** that server is included in the dynamic probe phase via stdio transport

#### Scenario: SSE server included in probe
- **WHEN** a server URL supports only SSE and Streamable HTTP handshake fails
- **THEN** the server is probed via SSE transport fallback

#### Scenario: Transport failures logged but don't block
- **WHEN** a server cannot be reached via any transport
- **THEN** an INFO finding is recorded with the transport error
- **AND** probing continues with the next server

### Requirement: Auth-aware probing
The system SHALL apply authentication configuration (headers, tokens, certificates) when connecting to MCP servers. Servers requiring auth that are missing credentials SHALL be reported with an INFO finding noting the auth gap rather than a connection error.

#### Scenario: Authenticated probe succeeds
- **WHEN** `ServerEntry.AuthToken` is set and the server requires Bearer auth
- **THEN** the MCP handshake and SSRF probes complete using the provided token

#### Scenario: Missing auth detected
- **WHEN** a server returns HTTP 401 or 403 and no auth is configured
- **THEN** an INFO finding reports "server requires authentication, none configured"

## MODIFIED Requirements

### Requirement: MCP JSON-RPC handshake
The system SHALL implement a minimal MCP JSON-RPC 2.0 client supporting the `initialize` request and response to establish a session with an MCP server before probing. The client SHALL support stdio, SSE, and Streamable HTTP transports. Transport selection SHALL be automatic based on server config.

#### Scenario: Successful HTTP handshake
- **WHEN** connecting to a valid MCP server over Streamable HTTP
- **THEN** the client sends `initialize` with protocol version "2024-11-05" and receives a valid response with server capabilities

#### Scenario: Successful stdio handshake
- **WHEN** connecting to a valid MCP server via stdio subprocess
- **THEN** the client sends `initialize` as a JSON-RPC line to stdin and receives a valid response from stdout

#### Scenario: Successful SSE handshake
- **WHEN** connecting to a valid MCP server over SSE
- **THEN** the client discovers the message endpoint via `/sse`, POSTs `initialize`, and receives a valid response via the event stream

#### Scenario: Handshake timeout
- **WHEN** the MCP server does not respond within the transport-specific timeout (5s HTTP, 5s stdio, 10s SSE)
- **THEN** the probe records a connection timeout and moves to the next server

#### Scenario: Non-MCP endpoint
- **WHEN** the endpoint returns non-JSON or a non-MCP response
- **THEN** the probe records an error and skips SSRF testing for that server (cannot determine protocol support)
