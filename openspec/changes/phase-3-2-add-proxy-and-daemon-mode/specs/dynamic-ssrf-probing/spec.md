# dynamic-ssrf-probing Delta Specification

## ADDED Requirements

### Requirement: MCP client inspection callbacks
The MCP client SHALL support optional `OnRequest` and `OnResponse` callback hooks invoked on each JSON-RPC call. These SHALL be used by proxy mode for real-time traffic inspection without modifying the client's core send/receive logic.

#### Scenario: Request callback invoked
- **WHEN** a `tools/call` is sent through a client with an `OnRequest` hook
- **THEN** the hook receives the method name, params, and is called before the request is sent

#### Scenario: Response callback invoked
- **WHEN** a `tools/list` response is received through a client with an `OnResponse` hook
- **THEN** the hook receives the method name, result, and response time after the response is parsed
