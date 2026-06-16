## ADDED Requirements

### Requirement: MCP client interface
The system SHALL define a `Client` interface in the `mcp` package exposing `Initialize`, `ListTools`, and `CallTool` methods, satisfied by the existing HTTP-backed client struct.

#### Scenario: Interface satisfaction
- **WHEN** the concrete `mcp.Client` struct is compiled
- **THEN** it satisfies the `Client` interface without adapter code

#### Scenario: Caller uses interface type
- **WHEN** a function accepts `mcp.Client` (interface type)
- **THEN** tests can supply a fake implementation without importing `net/http/httptest`

#### Scenario: Compile-time check
- **WHEN** the package is compiled
- **THEN** a `var _ Client = (*client)(nil)` assertion ensures the concrete type satisfies the interface
