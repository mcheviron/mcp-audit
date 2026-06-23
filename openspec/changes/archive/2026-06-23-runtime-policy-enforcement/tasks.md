## 1. Policy types and file parsing

- [x] 1.1 Define `PolicyConfig`, `PolicyRule`, and `PolicyCondition` structs with YAML/JSON tags in `internal/proxy/policy.go`
- [x] 1.2 Implement `LoadPolicy(path string) (*PolicyConfig, error)` that reads, unmarshals YAML (via JSON intermediate as in parser_toml.go), sorts rules by priority ascending, and validates required fields
- [x] 1.3 Write unit tests for `LoadPolicy` covering valid file, missing file, malformed YAML, unknown action, duplicate priorities, missing required fields

## 2. Rule evaluation engine

- [x] 2.1 Implement `PolicyEngine.Evaluate(method, tool string, params map[string]any) (action, description string)` that scans rules in priority order, matches method/tool with glob support, evaluates conditions with equals/contains/regex/prefix/suffix operators
- [x] 2.2 Implement condition extraction from nested params (dot-separated paths like `params.arguments.url` → traverse map)
- [x] 2.3 Write unit tests for Evaluate covering: allow first match, deny overrides lower-priority allow, default-deny, glob method matching, glob tool matching, each condition operator, condition AND logic, regex timeout

## 3. Proxy integration

- [x] 3.1 Add `Policy *PolicyEngine` and `DefaultDeny bool` fields to `proxy.Config`; instantiate engine in `proxy.New` when policy path is provided
- [x] 3.2 Integrate policy evaluation into `Handler()` director: after extracting method/tool from request body, call `Evaluate` before forwarding; on deny action, short-circuit by swapping target to a no-op handler that returns the deny error response
- [x] 3.3 Wire `--policy` and `--default-deny` flags in `cmd/mcp-audit/proxy_cmd.go`

## 4. Session counters

- [x] 4.1 Add `sync.Map` based counters to `PolicyEngine`: `TotalRequests int64`, `ToolCounts map[string]int64`; increment in Evaluate on each call
- [x] 4.2 Add `GET /__audit/stats` debug endpoint to proxy returning JSON with total requests and per-tool counts (only enabled when `--policy` is set)
- [x] 4.3 Write unit test verifying counter increments across multiple Evaluate calls

## 5. Policy validation subcommand

- [x] 5.1 Add `proxy policy validate <file>` subcommand to `cmd/mcp-audit/proxy_cmd.go` that loads policy via LoadPolicy and reports errors
- [x] 5.2 Write unit test for validate subcommand: valid policy exits 0, invalid exits 1 with error message

## 6. End-to-end tests

- [x] 6.1 Add e2e test in `e2e/e2e_policy_test.go`: start proxy with deny-rule policy, send request that matches deny rule, verify error response returned with code -32001
- [x] 6.2 Add e2e test: start proxy with audit-rule policy, send request matching audit rule, verify request forwarded and WARN log emitted
- [x] 6.3 Add e2e test: start proxy with default-deny flag and no allow rules, verify all requests blocked
