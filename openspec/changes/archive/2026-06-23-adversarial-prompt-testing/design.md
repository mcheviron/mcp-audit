## Context

Current tool description analysis (`internal/scanner/tool_analysis.go`) runs regex patterns directly on raw description strings. It catches explicit injection text but misses anything obfuscated with Unicode tricks, Base64 encoding, bidirectional overrides, or confusable characters. AgentSeal v0.8.0 catches these via a multi-stage deobfuscation pipeline plus adversarial probes against live servers.

## Goals / Non-Goals

**Goals:**
- 150+ deterministic adversarial probes (extraction, injection, role-switching, obfuscation bypass)
- Deobfuscation pipeline: Unicode tags, Base64, BiDi overrides, zero-width chars, TR39 confusables
- Trust scoring 0-100 from probe results
- Deobfuscation integrated as pre-processing before existing regex checks
- Probe library stored as embedded text file (`//go:embed`)

**Non-Goals:**
- Semantic similarity (MiniLM-L6-v2 equivalent) — requires Python/ONNX runtime
- All 225 AgentSeal probes — 150 prioritized for MCP context
- Probe mutation/adaptation — static library
- Client-side system prompt extraction — probes target MCP servers only

## Decisions

### Decision 1: Probe library as `//go:embed` text file

Probes stored in `internal/scanner/probes.txt`, one per line with pipe-delimited fields: `ID|category|description|probe_text`. Loaded at init via `//go:embed`. Parsed into `[]Probe` structs.

**Alternative:** Go source code string slices. Rejected — 150+ multi-line probe strings would bloat the file and make editing probes tedious. Text file is easier to maintain and verify.

### Decision 2: Deobfuscation as pipeline of pure functions

`func deobfuscate(desc string) (clean string, findings []Finding)`. Each stage is a function `func(desc string) (string, []Finding, bool stop)`. Pipeline iterates stages; on `stop=true`, remaining stages skipped. Order: (1) Unicode tags, (2) BiDi, (3) zero-width, (4) Base64, (5) TR39.

**Alternative:** All stages run in parallel, merge results. Rejected — stages are sequential by design (each operates on previous output). Running in parallel would require merging conflicting deobfuscated strings.

### Decision 3: TR39 confusable map as embedded JSON

Maintain a minimal confusable map in `internal/scanner/confusables.json` (`//go:embed`). Map format: `{"0435": "e", "04D5": "e", ...}` for Cyrillic/Greek/Latin confusables relevant to ASCII. Full TR39 is thousands of entries; we include only the subset confusable with ASCII a-z, 0-9, and common symbols.

**Alternative:** Full TR39 via external lib. Rejected — no stdlib Unicode confusable API; embed minimal subset.

### Decision 4: Adversarial probes only via dynamic mode

Probes require connecting to live MCP servers. They run as an opt-in `--adversarial` flag on `scan` and `probe` commands. Not part of `static` (no network). All probes read-only — no filesystem writes, no command execution.

## Risks / Trade-offs

- [Risk] 150 probes × 3 tools × N servers = significant runtime (up to 1500 requests per server at 5s timeout each) → Mitigation: `--adversarial-max-probes` flag limits probe count; default sends max 30 probes per server
- [Risk] False positives from probes matching normal tool behavior → Mitigation: analysis regexes are context-aware (look for prompt/system response patterns, not just keyword presence)
- [Risk] Base64 false positives on legitimate Base64 content → Mitigation: only flag decoded content that matches injection patterns
