## Why

mcp-audit's current analysis is passive: it inspects tool descriptions and responses for known patterns. It does not actively probe MCP servers to test their resistance to prompt injection, system prompt extraction, or tool description poisoning. AgentSeal v0.8.0 provides 225 deterministic adversarial probes (extraction, injection, mutation transforms) and deobfuscation-based tool description poisoning detection (Unicode tags, Base64, BiDi overrides, zero-width chars, TR39 confusables, MiniLM-L6-v2 similarity). MCP-38 (arXiv 2603.18063) identifies tool description poisoning and indirect prompt injection as MCP-specific attack categories not covered by traditional threat frameworks.

## What Changes

- Add a **prompt injection probe library** with 150+ deterministic probes (extraction, injection, role-switching, obfuscation bypass) — subset of AgentSeal's 225, prioritized by MCP relevance
- Add a **tool description poisoning detector** with deobfuscation pipeline: Unicode tag stripping, Base64 decoding, BiDi override detection, zero-width character scanning, TR39 confusable detection
- New `mcp-audit probe --adversarial` mode that connects to discovered MCP servers, sends crafted adversarial inputs, and scores resistance on 0-100 trust scale
- Integrate poisoning detection into existing `tools/list` analysis pipeline
- Report adversarial findings separately from static/dynamic findings with dedicated severity band

## Capabilities

### New Capabilities

- `adversarial-probes`: Deterministic prompt injection/extraction probe library with obfuscation-aware deobfuscation and trust scoring
- `tool-description-poisoning`: Deobfuscation pipeline for detecting hidden instructions embedded in tool descriptions via Unicode tricks, encoding, and confusable characters

### Modified Capabilities

- `tool-security-analysis`: Tool description inspection now runs through the deobfuscation pipeline before regex matching, catching encoded/obfuscated injection patterns that current regex misses.

## Impact

- `internal/scanner/` — new `adversarial.go`, `adversarial_test.go` (probe library + poisoning detector)
- `internal/scanner/dynamic.go` — new adversarial probe mode integrated into dynamic probing flow
- `internal/scanner/tool_analysis.go` — integrate deobfuscation pre-processing before existing regex checks
- `cmd/mcp-audit/main.go` — new `--adversarial` flag on probe/scan commands
- `internal/report/` — new `SevAdversarial` severity level or adversarial finding tag
- Unicode handling via stdlib `unicode`, `unicode/utf8`; no external deps

## Non-goals

- LLM-based semantic similarity for poisoning detection — requires external model (AgentSeal uses MiniLM-L6-v2, which is Python)
- All 225 AgentSeal probes — implement the 150 most MCP-relevant ones
- Adaptive/mutation-based probes — static probe library only
- System prompt extraction from AI clients — probes target MCP servers, not the client's LLM
