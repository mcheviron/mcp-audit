## Why

Tool description poisoning is the #1 documented MCP attack vector per OWASP MCP Top 10 (MCP03), the CSA MCP Security Crisis report (May 2026), and five academic papers. Adversaries embed hidden directives in tool descriptions that the AI model consumes but users never see. The current tool fetches tool descriptions via `ListTools` but never inspects them for security. A 2026 census of 1,360 MCP servers found 27.2% contain threat-relevant tools. The tool also has zero capability to analyze tool schemas for dangerous operations (file write, shell exec, network access) — a gap MCPShield covers.

## What Changes

- Inspect `Tool.Description` for prompt injection patterns: hidden instructions, code blocks with adversarial content, role-switching directives, URL-based payloads
- Analyze `Tool.InputSchema` for dangerous capabilities: filesystem write paths, command execution patterns, unrestricted network access
- Cross-server tool description comparison: detect when one server's description manipulates behavior of other trusted servers (cross-origin escalation / tool shadowing per OWASP MCP03.2)
- Analyze tool return values (`CallToolResult.Content`) for prompt injection patterns and hidden directives
- Flag tools with no descriptions (information hiding) and tools with overly broad schema definitions
- Add `--tool-analysis` flag (default: on) and severity classification for tool security findings

## Capabilities

### New Capabilities

- `tool-security-analysis`: Static and dynamic analysis of MCP tool descriptions, input schemas, and return values for prompt injection, dangerous capabilities, tool shadowing, and information hiding.

### Modified Capabilities

- `dynamic-ssrf-probing`: Extend response analysis to include tool-return-value prompt injection detection alongside existing credential/SSRF checks.

## Impact

- `internal/scanner/analysis.go` — new analysis functions: `analyzeToolDescription`, `analyzeToolSchema`, `analyzeToolShadowing`, `analyzeToolResponse`
- `internal/scanner/dynamic.go` — call tool analysis during `runMCPProbes` after `ListTools` succeeds
- `internal/scanner/static.go` — new `checkToolSecurity` function for config-level tool analysis
- `main.go` — `--tool-analysis` flag (default true), `--no-tool-analysis` to disable

## Non-Goals

- Full NLP/LLM-based description analysis — start with regex and heuristic pattern matching
- Sandbox escape detection through tool behavior (requires behavioral analysis, separate proposal)
- Tool definition integrity verification across sessions (rug pull detection, separate proposal)
- Content embedding or ML-based analysis (separate proposal for response analysis)
