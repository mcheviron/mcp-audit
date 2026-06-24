## Why

mcp-audit's CVE scanning produces flat, disconnected results: a CVE against a package, separate from credential findings and tool capability classifications. Agent-BOM provides BFS traversal blast-radius chains (CVE → package → MCP server → agent → credentials → tools) showing the full impact path. Agent-BOM also maps findings to 10 compliance frameworks (FedRAMP, CMMC, NIST AI RMF, ISO 27001, SOC 2, OWASP LLM Top-10, MITRE ATLAS, EU AI Act) and generates tamper-evident evidence bundles. Users cannot answer "if this CVE is exploited, what credentials are exposed?" from mcp-audit output today.

## What Changes

- Add **blast-radius dependency chain** computation: BFS traversal linking CVE findings → affected packages → MCP servers → agent configurations → tools → credential findings, configurable depth (default 3 hops)
- Add **compliance framework mapping**: each finding tagged with relevant control IDs from SOC 2, NIST AI RMF, OWASP LLM Top-10, MITRE ATLAS, and EU AI Act frameworks
- New `mcp-audit scan --blast-radius` flag and `--compliance-framework` flag filtering output by framework
- SARIF and JSON output extended with `relatedFindings`, `blastRadiusChain`, and `complianceTags` fields
- Evidence bundle export (`--export-evidence`) producing signed JSON with HMAC-chained integrity

## Capabilities

### New Capabilities

- `blast-radius-chains`: BFS-based dependency chain computation linking CVEs, packages, servers, agents, credentials, and tools into impact graphs
- `compliance-mapping`: Mapping of scan findings to regulatory/compliance framework controls with filtering and reporting
- `evidence-export`: Tamper-evident signed JSON/JSONL evidence bundle export with HMAC-chained integrity

### Modified Capabilities

- `cve-vulnerability-scanning`: CVE findings now include backlinks to affected MCP servers, credential findings, and tool capability classifications

## Impact

- `internal/scanner/` — new `blast_radius.go`, `blast_radius_test.go`, `compliance.go`, `compliance_test.go`
- `internal/scanner/cve.go` — add cross-reference fields to CVE results
- `internal/report/sarif.go` — add `relatedFindings` and `complianceTags` to SARIF output
- `internal/report/format.go` — compliance framework column in table output
- `cmd/mcp-audit/main.go` — new `--blast-radius`, `--blast-radius-depth`, `--compliance-framework`, `--export-evidence` flags
- `internal/report/evidence.go` — HMAC-chained JSON export

## Non-goals

- Container image/IaC scanning — Agent-BOM's Trivy integration requires external deps
- All 10 Agent-BOM frameworks — start with 5 (SOC 2, NIST AI RMF, OWASP LLM Top-10, MITRE ATLAS, EU AI Act)
- Real-time blast-radius updates on new CVEs — computed at scan time only
- FedRAMP/CMMC/ISO 27001/HIPAA/PCI-DSS mappings — deferred to follow-up
