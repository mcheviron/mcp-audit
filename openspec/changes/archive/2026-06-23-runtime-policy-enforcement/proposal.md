## Why

The proxy currently has a single boolean `--block-critical` flag and hardcoded regex inspection. It cannot express per-tool, per-method, or per-condition access policies. MCPGuard already provides a YAML policy firewall with allow/deny/audit actions, priority-based rule matching, and field-operator-value conditions. CSA AIUC-1 Q2 2026 now mandates runtime containment controls that "limit lateral movement within the execution environment" — a requirement our inspection-only proxy does not meet.

## What Changes

- Add a **YAML policy file** defining rules with allow/deny/audit actions, priority ordering, and field-operator-value conditions on JSON-RPC method, tool name, and parameters
- Extend the proxy to load and evaluate policies **per-request**, blocking or auditing based on matching rules
- Add **session-scoped authorization** tracking: agent identity, per-session tool call history, rate-limit counters
- Add a `--policy` flag to the proxy command and a `proxy policy validate` subcommand for offline policy testing
- Introduce a **default-deny mode** with explicit allowlisting as fallback when no policy file is specified

## Capabilities

### New Capabilities

- `policy-engine`: YAML-based rule evaluation engine with allow/deny/audit actions, priority matching, and field-operator-value conditions

### Modified Capabilities

- `proxy-mode`: Upgrade from hardcoded `--block-critical` boolean to full policy-driven request evaluation. Existing inspection pipeline remains; policy engine wraps it as pre-check layer.

## Impact

- `internal/proxy/` — new `policy.go`, `policy_test.go`; modify `proxy.go` to integrate policy evaluation
- `cmd/mcp-audit/` — new `--policy` flag on proxy command, new `proxy policy validate` subcommand
- `internal/configfile/` — policy file format alongside existing config types
- No external dependencies; YAML parsing uses `encoding/json` + manual struct unmarshaling (consistent with existing pattern)

## Non-goals

- Network-level firewall or eBPF-based containment — this is application-layer policy only
- Policy distribution or remote policy fetching — local files only
- LDAP/OIDC integration for agent identity — agent identity is header-based only
