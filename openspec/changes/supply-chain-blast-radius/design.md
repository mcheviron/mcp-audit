## Context

Current CVE scanning (`internal/scanner/cve.go`, `cve_scan.go`) produces `Result` entries with CVE ID, CVSS score, package name, and description — no links to other findings. Blast-radius chains require joining CVE results with credential findings and tool analysis results after all scanning phases complete.

## Goals / Non-Goals

**Goals:**
- BFS chain computation at scan-end from all finding types
- Finding cross-references in CVE results
- 5 compliance framework mappings (SOC 2, NIST AI RMF, OWASP LLM Top-10, MITRE ATLAS, EU AI Act)
- HMAC-chained evidence export
- Framework filtering for output

**Non-Goals:**
- Container/IaC scanning
- Full ISO 27001, FedRAMP, CMMC, HIPAA, PCI-DSS mappings
- Incremental blast-radius updates

## Decisions

### Decision 1: BFS on in-memory finding graph

Build adjacency list at scan-end: CVE findings keyed by package name, credential/tool findings keyed by server name, config files keyed by path. BFS from each CVE, following edges: CVE → server (by package name match) → config (by server name) → tools (by server name) → credentials (by server name). O(V+E) per CVE, V ≤ 1000 for realistic scans.

**Alternative:** Pre-indexed graph during scan. Rejected — adds mutable state during scanning; post-hoc BFS is simpler and avoids synchronization.

### Decision 2: Compliance mappings as embedded JSON

Each framework gets `internal/scanner/compliance/<framework>.json` embedded via `//go:embed`. Format: `{"finding_types": {"credential_leak": ["CC6.1"], "prompt_injection": ["LLM01"]}}`. Mapping function `MapToCompliance(findingType string, severity Severity) []Control` looks up finding type → controls.

**Alternative:** Hardcoded Go maps. Rejected — JSON files are easier to audit, update, and contribute to.

### Decision 3: HMAC chain via SHA256

Each evidence entry: `{id, data, prev_hash}`. `hash = HMAC-SHA256(key, id || data || prev_hash)`. Chain integrity verified by recomputing all hashes with same key. Key printed to stderr on scan start, NOT included in bundle.

**Alternative:** Digital signatures (ed25519). Rejected — requires key pair generation and management; HMAC is simpler for local evidence use case.

## Risks / Trade-offs

- [Risk] Blast-radius chains may over-link when server names are generic → Mitigation: chain nodes include `match_type` (exact/partial) for transparency
- [Risk] Compliance mappings may become outdated → Mitigation: version field in each mapping file; update process documented
- [Risk] Large evidence bundles (1000+ findings) with HMAC chain → Mitigation: chunked JSONL format with per-chunk HMAC for bundles over 1MB
