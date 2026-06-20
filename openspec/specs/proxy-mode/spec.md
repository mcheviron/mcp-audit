# proxy-mode Specification

## Purpose
Transparent MCP proxy auditing all JSON-RPC traffic between AI client and MCP server with real-time inspection and optional blocking.

## Requirements

### Requirement: Transparent HTTP proxy
The system SHALL start an HTTP reverse proxy that forwards requests from an AI client to a target MCP server. The proxy SHALL inspect all JSON-RPC requests and responses. Tool descriptions from `tools/list` responses and tool call results from `tools/call` responses SHALL be analyzed using the existing tool security and SSRF analysis pipelines.

#### Scenario: tools/list inspection
- **WHEN** the client sends a `tools/list` request through the proxy
- **THEN** the proxy forwards it to the target server and inspects the response for tool description injection and dangerous capabilities

#### Scenario: tools/call inspection
- **WHEN** the client sends a `tools/call` request through the proxy
- **THEN** the proxy inspects both the request arguments (for SSRF indicators) and the response (for credential leakage and prompt injection)

### Requirement: Blocking mode
The system SHALL support `--block-critical` flag. When enabled and analysis detects a CRITICAL finding, the proxy SHALL return an MCP error response to the client instead of forwarding the server response.

#### Scenario: Critical finding blocked
- **WHEN** `--block-critical` is set and a server response contains AWS credentials
- **THEN** the proxy returns `{"jsonrpc": "2.0", "error": {"code": -32000, "message": "Blocked by mcp-audit: AWS credentials detected"}}`

#### Scenario: Non-blocking mode
- **WHEN** `--block-critical` is not set
- **THEN** all traffic is forwarded normally with findings logged only

### Requirement: Proxy logging
The system SHALL log all proxied JSON-RPC method calls and responses to stderr at INFO level. Request and response bodies SHALL be logged at DEBUG level with `--verbose`.

#### Scenario: Proxy traffic logged
- **WHEN** a `tools/call` request passes through the proxy
- **THEN** the method name, tool name, and response time are logged to stderr

### Requirement: Graceful shutdown
The proxy SHALL handle SIGTERM and SIGINT signals by gracefully shutting down the HTTP server. The shutdown SHALL allow up to 30 seconds for inflight requests to complete before forcing connections closed. The proxy command SHALL use `signal.NotifyContext` to derive a cancellation context passed to the proxy's `Start` method.

#### Scenario: SIGTERM triggers graceful shutdown
- **WHEN** the proxy process receives SIGTERM
- **THEN** the HTTP server calls `Shutdown(ctx)` with a 30-second grace period and exits cleanly

#### Scenario: Inflight requests complete during shutdown
- **WHEN** a proxy request is in-flight during shutdown
- **THEN** the request completes normally before the server closes

#### Scenario: Second signal forces exit
- **WHEN** a second SIGTERM or SIGINT is received during graceful shutdown
- **THEN** the process exits immediately

### Requirement: Upstream TLS configuration
The system SHALL support `--upstream-ca-cert`, `--upstream-cert`, and `--upstream-key` flags for the proxy command. When set, the proxy SHALL configure a custom `http.Transport` with the specified TLS client certificates and CA certificate pool for connections to the upstream MCP server. When no TLS flags are set, the proxy SHALL use the default HTTP transport.

#### Scenario: Custom CA certificate for upstream
- **WHEN** `--upstream-ca-cert ca.pem` is set
- **THEN** the proxy's upstream TLS connections trust the specified CA certificate

#### Scenario: mTLS for upstream
- **WHEN** `--upstream-cert client.pem` and `--upstream-key client-key.pem` are set
- **THEN** the proxy presents the client certificate during TLS handshake with the upstream MCP server

#### Scenario: Default transport when no TLS flags set
- **WHEN** no upstream TLS flags are set
- **THEN** the proxy uses `http.DefaultTransport` for upstream connections (current behavior preserved)
