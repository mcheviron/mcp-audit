## Context

Current proxy (`internal/proxy/proxy.go`) does hardcoded inspection: regex patterns for SSRF indicators, credential patterns, prompt injection. Blocking is a single boolean `BlockCritical` that blocks AFTER the request reaches the target server and the response comes back. No per-tool rules, no parameter-based conditions, no allowlisting.

MCPGuard provides a YAML policy firewall. CSA AIUC-1 Q2 2026 mandates runtime containment. Users need configurable, fine-grained access control — not just "block all critical findings."

## Goals / Non-Goals

**Goals:**
- YAML policy file with allow/deny/audit actions, priority ordering, field-operator-value conditions
- Policy evaluation as pre-check layer BEFORE request forwarding
- Session-scoped counters (requests total, per-tool invocation count)
- `proxy policy validate` offline validation command
- Default-deny mode
- Zero external dependencies — stdlib YAML via struct tags (consistent with existing TOML parser pattern)

**Non-Goals:**
- Policy hot-reload — restart required for policy changes
- Remote policy fetching — local files only
- Agent identity via OIDC/LDAP — header-based only
- Rate limiting enforcement — counters only, no blocking by count

## Decisions

### Decision 1: Policy file format as YAML with JSON-compatible types

Use the same manual YAML-unmarshaling pattern already used for TOML config parsing (`internal/config/parser_toml.go`): define a `PolicyConfig` struct with YAML struct tags, marshal to JSON, unmarshal into struct.

**Alternative considered:** External YAML library (`gopkg.in/yaml.v3`). Rejected — violates stdlib-first constraint. Existing codebase already parses YAML-like formats via manual JSON intermediate step.

**Format:**
```yaml
rules:
  - action: deny
    priority: 10
    method: tools/call
    tool: run_command
    description: "Block command execution"
    conditions:
      params.arguments.command:
        op: regex
        value: "rm\\s+-rf"
  - action: allow
    priority: 20
    method: tools/list
  - action: audit
    priority: 30
    method: "*"
```

### Decision 2: Policy evaluation as Director middleware

Integrate policy evaluation into the existing `director` function in `Handler()`. Before extracting the method from the body for inspection, evaluate the request against the policy engine. If denied, short-circuit by modifying the request to target a no-op handler. This avoids adding a separate HTTP middleware layer and keeps all request preprocessing in one place.

**Alternative considered:** Separate `http.Handler` wrapper. Rejected — would require body consumption twice (once for policy, once for inspection). Single-pass body reading in director avoids this.

### Decision 3: Rule evaluation via priority-ordered linear scan

Iterate rules sorted by priority (ascending). First match wins. O(n) per request, acceptable for policy files expected to be <200 rules. Conditions ANDed — all must match.

**Alternative considered:** Trie/radix tree for method+tool matching. Rejected — over-engineering for the expected scale.

### Decision 4: Session state in-memory only

Counters stored in `sync.Map` on the Proxy struct. Lost on restart. No persistence needed — policy counters are for observability, not enforcement.

## Risks / Trade-offs

- [Risk] Large policy files (>1000 rules) could add measurable latency per request → Mitigation: document expected scale, benchmark with 1000-rule policy
- [Risk] Regex conditions could ReDoS if user supplies pathological patterns → Mitigation: compile regexes at policy load time with `regexp.Compile` and enforce a 100ms timeout per regex evaluation using context
- [Risk] YAML parsing without a library is error-prone for complex nested structures → Mitigation: comprehensive validation in `proxy policy validate` command catches edge cases before runtime
