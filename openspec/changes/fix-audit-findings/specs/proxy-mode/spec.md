## ADDED Requirements

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
