## Context

The MCP client currently calls `ListTools` (protocol.go:62-69) and passes tools to `probeMCPTool` (analysis.go:271-297), which reads `InputSchema` only to find URL-like parameters for SSRF crafting. `Tool.Description` (protocol.go:68) is fetched but never read by any scanner. This is a critical blind spot: tool descriptions are the primary attack surface for prompt injection, yet the auditor doesn't inspect them.

OWASP MCP Top 10 classifies MCP03 (Tool Poisoning) with three sub-techniques: description-based injection, return-value poisoning, and cross-origin tool shadowing. Production tools (MCPShield, mcp-safeguard, @mcp-server-shield/guard) all perform description and schema inspection.

## Goals / Non-Goals

**Goals:**
- Detect prompt injection patterns in tool descriptions (hidden instructions, role-switching, code blocks with adversarial content)
- Classify tool capabilities from InputSchema (filesystem, network, shell, database) and flag dangerous ones
- Detect tool shadowing: same-named tools across servers with differing descriptions or schemas
- Analyze tool return values for injection patterns during SSRF probing
- Heuristic-based — regex patterns, keyword matching, structural analysis
- Flag missing descriptions and overly broad schemas as INFO findings

**Non-Goals:**
- LLM-based semantic analysis (too heavy, too slow, external dep)
- Behavioral execution of tools to verify declared capabilities
- Cross-session tool definition drift (separate rug pull proposal)
- Content embeddings for response analysis (separate proposal)

## Decisions

### Pattern-based description analysis, not LLM

Regex and keyword heuristics catch the known injection techniques documented in OWASP and CSA research: hidden system prompts (`You are now`, `Ignore previous`, `system:` directives), role-switching (`act as`, `you must`), URL embeds, and base64-encoded blocks. False positive rate is acceptable — flagged descriptions are shown to user for review, not auto-blocked.

Alternative: call an LLM to analyze descriptions. Rejected — adds latency, cost, and external dependency. Against project's zero-dep ethos.

### Tool capability classification from JSON Schema

Parse `InputSchema` properties for capability indicators:
- `filesystem`: properties named `path`, `file`, `directory`; type `string` with `format: file-path`
- `network`: properties named `url`, `uri`, `endpoint`, `host`; type `string` with `format: uri`
- `shell`: properties named `command`, `cmd`, `script`; type `string`
- `database`: properties named `query`, `sql`, `collection`; type `string`

Flag tools with multiple capability classes as higher risk.

### Tool shadowing: name+server key comparison

Within a single scan, if two different servers expose tools with the same name but different descriptions or schemas, flag as potential shadowing. This doesn't require cross-session storage — it's in-memory during one probe run.

### Return value analysis: reuse existing analysis pipeline

`evalToolTextBlock` in analysis.go already checks tool responses for credentials and internal content. Add prompt injection patterns as a new check layer, reusing the same text block iteration.

## Risks / Trade-offs

- **False positives on benign descriptions** → Training material, documentation-style descriptions may match injection patterns. Mitigation: findings are INFO severity (advisory), not CRITICAL.
- **Pattern evasion** → Adversaries can craft descriptions that avoid regex matches. Mitigation: acknowledge this is a heuristic layer, not a guarantee. Future: content embeddings.
- **Schema parsing edge cases** → JSON Schema is expressive; `oneOf`, `anyOf`, `$ref` can hide capabilities. Mitigation: parse only top-level `properties` (same as current `buildProbeArgs`). Complex schemas get INFO "complex schema, manual review recommended."

## Open Questions

- Should tool capability classification influence probe behavior? (e.g., skip tools classified as filesystem-only since they can't make HTTP requests for SSRF)
- What threshold of "overly broad schema" triggers a finding? (e.g., no properties defined, or `additionalProperties: true` with no constraints)
