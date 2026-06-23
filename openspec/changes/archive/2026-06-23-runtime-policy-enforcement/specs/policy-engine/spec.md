## ADDED Requirements

### Requirement: YAML policy file loading
The system SHALL load a YAML policy file specified via `--policy <path>`. The policy file SHALL define rules as an ordered list with fields: `action` (allow/deny/audit), `priority` (integer, lower runs first), `method` (JSON-RPC method name, exact or glob), `tool` (tool name pattern), and `conditions` (map of field-operator-value triples).

#### Scenario: Policy file loaded successfully
- **WHEN** the proxy starts with `--policy policy.yaml` and the file exists and is valid
- **THEN** the proxy loads all rules and evaluates each request against them in priority order

#### Scenario: Missing policy file
- **WHEN** the proxy starts with `--policy missing.yaml` and the file does not exist
- **THEN** the proxy exits with a non-zero exit code and an error message

#### Scenario: Invalid policy syntax
- **WHEN** the proxy starts with `--policy invalid.yaml` containing malformed YAML
- **THEN** the proxy exits with a non-zero exit code and a parse error message

### Requirement: Rule matching by method
The system SHALL match incoming JSON-RPC requests against policy rules by comparing the `method` field. Rule method values SHALL support exact match and trailing `*` glob (e.g., `tools/call*` matches `tools/call` and `tools/call/result`).

#### Scenario: Exact method match
- **WHEN** a `tools/list` request arrives and a rule specifies `method: tools/list`
- **THEN** the rule matches

#### Scenario: Glob method match
- **WHEN** a `tools/call` request arrives and a rule specifies `method: tools/*`
- **THEN** the rule matches

#### Scenario: Method mismatch
- **WHEN** a `initialize` request arrives and a rule specifies `method: tools/list`
- **THEN** the rule does not match

### Requirement: Rule matching by tool name
The system SHALL match tool names from `params.name` in `tools/call` requests against the `tool` field in policy rules. Tool patterns SHALL support exact match and trailing `*` glob.

#### Scenario: Tool name exact match
- **WHEN** a `tools/call` for tool `read_file` arrives and a rule specifies `tool: read_file`
- **THEN** the rule matches

#### Scenario: Tool name glob match
- **WHEN** a `tools/call` for tool `read_file` arrives and a rule specifies `tool: read_*`
- **THEN** the rule matches

### Requirement: Condition-based matching
The system SHALL evaluate `conditions` on rule entries as a map of field paths to operator-value comparisons. Supported operators SHALL be `equals`, `contains`, `regex`, `prefix`, and `suffix`. All conditions in a rule SHALL be ANDed together.

#### Scenario: Single condition match
- **WHEN** a rule has `conditions: {params.arguments.path: {op: contains, value: "/etc"}}` and the request contains `params.arguments.path: "/etc/passwd"`
- **THEN** the condition matches

#### Scenario: All conditions must match
- **WHEN** a rule has two conditions and only one is satisfied
- **THEN** the rule does not match

#### Scenario: Regex condition
- **WHEN** a rule has `conditions: {params.arguments.url: {op: regex, value: "https?://internal\\.corp"}}` and the request contains `params.arguments.url: "http://internal.corp/api"`
- **THEN** the condition matches

### Requirement: Policy actions
The system SHALL support three actions per rule: `allow` (forward the request), `deny` (return MCP error response), and `audit` (forward but log at WARN level). The first matching rule in priority order SHALL determine the action.

#### Scenario: Allow action
- **WHEN** a matching rule has `action: allow`
- **THEN** the request is forwarded to the target server

#### Scenario: Deny action
- **WHEN** a matching rule has `action: deny`
- **THEN** the proxy returns `{"jsonrpc": "2.0", "error": {"code": -32001, "message": "Denied by policy: <rule description>"}}`

#### Scenario: Audit action
- **WHEN** a matching rule has `action: audit`
- **THEN** the request is forwarded AND a WARN log entry is emitted with the matched rule description

### Requirement: Default-deny mode
The system SHALL support a `--default-deny` flag on the proxy command. When set, any request not matching an explicit `allow` rule SHALL be denied.

#### Scenario: Default deny blocks unmatched request
- **WHEN** `--default-deny` is set and no rule matches the incoming request
- **THEN** the proxy returns a deny error response

#### Scenario: Default allow without flag
- **WHEN** `--default-deny` is not set and no rule matches the incoming request
- **THEN** the request is forwarded normally

### Requirement: Session-scoped request counting
The system SHALL track per-session counters for total requests and per-tool invocation counts. Counters SHALL be scoped to the proxy instance lifetime.

#### Scenario: Per-tool count tracked
- **WHEN** three `tools/call` requests for tool `run_command` pass through the proxy
- **THEN** the session counter for `run_command` reads 3

#### Scenario: Counters reset on restart
- **WHEN** the proxy process is restarted
- **THEN** all session counters are reset to zero

### Requirement: Policy validation subcommand
The system SHALL provide a `proxy policy validate <file>` subcommand that loads and validates a policy file without starting the proxy, reporting syntax errors and semantic issues (duplicate priorities, unknown actions, missing required fields).

#### Scenario: Valid policy passes validation
- **WHEN** `mcp-audit proxy policy validate valid-policy.yaml` is run on a valid policy file
- **THEN** the command exits with code 0 and prints "Policy valid"

#### Scenario: Invalid policy fails validation
- **WHEN** `mcp-audit proxy policy validate bad-policy.yaml` is run on a file with an unknown action
- **THEN** the command exits with code 1 and prints the validation error
