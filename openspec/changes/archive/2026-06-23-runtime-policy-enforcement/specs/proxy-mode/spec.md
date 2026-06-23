## MODIFIED Requirements

### Requirement: Transparent HTTP proxy
The system SHALL start an HTTP reverse proxy that evaluates each incoming JSON-RPC request against the loaded policy engine BEFORE forwarding to the target MCP server. When a policy file is specified via `--policy`, policy evaluation SHALL occur before the existing inspection pipeline. The proxy SHALL continue inspecting all JSON-RPC requests and responses through the existing tool security and SSRF analysis pipelines after policy evaluation. When no `--policy` flag is set, behavior SHALL be unchanged from the current implementation.

#### Scenario: Policy evaluated before forwarding
- **WHEN** `--policy rules.yaml` is set and a `tools/call` request matches a deny rule
- **THEN** the proxy returns a policy error without forwarding to the target server

#### Scenario: tools/list inspection with policy
- **WHEN** the client sends a `tools/list` request through the proxy with a policy allowing it
- **THEN** the proxy forwards it to the target server and inspects the response for tool description injection and dangerous capabilities

#### Scenario: tools/call inspection with policy
- **WHEN** the client sends a `tools/call` request through the proxy with a policy allowing it
- **THEN** the proxy inspects both the request arguments (for SSRF indicators) and the response (for credential leakage and prompt injection)

#### Scenario: No policy file — current behavior preserved
- **WHEN** the proxy starts without `--policy`
- **THEN** all requests are forwarded without policy evaluation, preserving existing behavior

### Requirement: Blocking mode
The system SHALL support `--block-critical` flag AND policy-driven blocking. When `--block-critical` is enabled and analysis detects a CRITICAL finding, the proxy SHALL return an MCP error response to the client instead of forwarding the server response. When a policy file is loaded and a request matches a `deny` rule, the proxy SHALL return a policy-denied error response BEFORE the request reaches the target server. Policy-based deny SHALL take precedence over `--block-critical` since it prevents the request entirely.

#### Scenario: Critical finding blocked
- **WHEN** `--block-critical` is set and a server response contains AWS credentials
- **THEN** the proxy returns `{"jsonrpc": "2.0", "error": {"code": -32000, "message": "Blocked by mcp-audit: AWS credentials detected"}}`

#### Scenario: Policy deny blocks before request
- **WHEN** a policy rule with `action: deny` matches the incoming request
- **THEN** the proxy returns `{"jsonrpc": "2.0", "error": {"code": -32001, "message": "Denied by policy: <description>"}}` without contacting the target server

#### Scenario: Policy allow with block-critical
- **WHEN** a policy allows the request but `--block-critical` is set and the server response triggers a CRITICAL finding
- **THEN** the response is blocked as before

#### Scenario: Non-blocking mode
- **WHEN** `--block-critical` is not set and no policy deny rules match
- **THEN** all traffic is forwarded normally with findings logged only
