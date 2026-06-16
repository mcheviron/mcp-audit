## Context

MCP (Model Context Protocol) is a JSON-RPC protocol for AI coding tools to interact with external services. MCP servers run as local subprocesses or HTTP endpoints and expose tools that AI agents can invoke. The ecosystem is growing rapidly — but 18-37% of servers have SSRF vulnerabilities. Existing tool MCPShield (Rust) does static config analysis only. No tool does runtime vulnerability probing.

mcp-audit is a greenfield Go CLI that fills this gap. Single binary, zero dependencies, stdlib-first. It scans MCP server configurations across 5 AI coding tools, detects typosquatted package names, and performs read-only SSRF probing against discovered endpoints.

## Goals / Non-Goals

**Goals:**
- Discover all MCP servers installed locally across Claude Desktop, Cursor, Windsurf, VS Code, Continue
- Detect typosquatted MCP package names via Levenshtein distance
- Probe MCP server endpoints for SSRF vulnerabilities with safe, read-only payloads
- Output results in terminal table, JSON, and SARIF formats
- Ship as a single static Go binary with zero runtime dependencies

**Non-Goals:**
- Destructive pentesting or exploitation (read-only audit only)
- Real-time filesystem watching or daemon mode
- MCP server fuzzing or coverage-guided input mutation
- GUI, web interface, or browser-based reporting
- OAuth token scope analysis

## Decisions

### Go over Rust
MCPShield already owns Rust mindshare in this space. The MCP auditor is I/O-bound (HTTP probes, config parsing) — goroutines are simpler than async Rust for concurrent network I/O with no performance difference. Go's stdlib covers every need (net/http, encoding/json, text/tabwriter) with zero external dependencies. Compile speed and single-binary cross-compilation make distribution trivial.

### Build MCP protocol client from scratch
Rather than depending on an MCP SDK, implement a minimal JSON-RPC client supporting only `initialize`, `tools/list`, and `tools/call`. This follows CodeCrafters ethos (understand every line), avoids SDK version churn, and keeps the dependency count at zero. The subset of MCP spec needed for SSRF probing is ~200 lines.

### Read-only probing with safety model
Dynamic probing is opt-in (`mcp-audit probe` or `--probe` flag with confirmation). Probes only request metadata endpoints (`/latest/meta-data/`, `/computeMetadata/v1/`) — never service APIs. Responses truncated at 4KB. Timeout 5s per probe, max 10 concurrent, 100ms inter-probe delay. Dry-run mode prints what would be probed without making requests.

### Config file discovery per-tool, not per-platform
Each AI tool stores MCP configs differently. Rather than abstracting over platforms (macOS/Linux/Windows), model each tool as a discrete config source with its own parser. Each parser knows its own default paths, JSON schema, and platform-specific locations. This keeps parsers small and testable.

### Severity classification
Five levels: CRITICAL (cloud metadata returned), HIGH (redirect to internal IP or internal HTTP response), MEDIUM (connection to internal IP, firewall may have blocked), LOW (open redirect, no internal target), INFO (potential typosquat), PASS (clean). This maps naturally to SARIF and gives actionable prioritization.

### Levenshtein from scratch
Implement edit-distance algorithm directly (15 lines, no dependency) rather than pulling a string-metrics library. The algorithm is well-known, the implementation is trivial, and keeping it internal avoids a dependency for a single function.

## Risks / Trade-offs

- **False positives on SSRF** → Cloud metadata services may respond differently across providers (IMDSv1 vs v2). Mitigation: probe both, classify responses conservatively, report uncertainty in output.
- **Probe safety** → Even read-only probes could trigger alerts on monitored internal networks. Mitigation: opt-in only, dry-run mode, allowlist/blocklist, clear warnings in documentation.
- **Config format drift** → AI tools may change their MCP config schema. Mitigation: each parser is ~50 lines and independently testable. Versioned fixture tests catch drift.
- **MCP spec evolution** → The MCP protocol is under active development. Mitigation: minimal protocol surface (3 message types), isolated in `internal/mcp/`, easy to update.
- **Typosquat DB staleness** → Known malicious package list will age. Mitigation: embed the initial list, design for external DB updates (post-MVP).

## Open Questions

- Should the typosquat DB be embedded at compile time (`//go:embed`) or loaded from a configurable URL/path for live updates?
- Should the tool auto-detect the OS and include Windows config paths, or start macOS-only and add platforms incrementally?
- What is the right severity for a server that returns a 404 on metadata endpoints (firewall blocked) vs connection refused (no listener)?
