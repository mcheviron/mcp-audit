# proxy-mode Specification

## Purpose
Transparent MCP proxy auditing all JSON-RPC traffic between AI client and MCP server with real-time inspection and optional blocking.

## ADDED Requirements

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
