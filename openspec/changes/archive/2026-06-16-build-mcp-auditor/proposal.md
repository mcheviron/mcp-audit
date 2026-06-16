## Why

18-37% of open-source MCP servers have SSRF vulnerabilities (confirmed across 3 independent studies, 7,500+ servers). Real CVEs exist (CVE-2025-65513, CVE-2026-45609, CVE-2026-27825/27826). MCPShield (Rust, 1.6k stars, 4 months old) validates demand for MCP security scanning but only does static config analysis — no tool does runtime SSRF probing. This project fills that gap with a single Go binary that developers run before deploying MCP servers or when auditing their local MCP toolchain.

## What Changes

- New Go CLI binary `mcp-audit` with three subcommands: `scan` (full audit), `static` (config-only), `probe` (dynamic SSRF only)
- Static config scanner: discovers and parses MCP server configurations across 6 AI coding tools (Claude Desktop, Cursor, Windsurf, VS Code, Continue, OpenCode)
- Typosquat detector: Levenshtein distance analysis against known legitimate and malicious MCP packages
- Dynamic SSRF prober: minimal MCP JSON-RPC client that performs read-only metadata endpoint probing against discovered servers
- Safety model: opt-in dynamic probing, rate limiting, response truncation, dry-run mode, allowlist/blocklist
- Report output: terminal table (default), JSON, SARIF (for CI integration)
- Zero external dependencies — stdlib only, single static binary distribution

## Capabilities

### New Capabilities
- `static-config-scanning`: Discover and parse MCP server configs from 6 AI coding tools, extract endpoints and metadata
- `typosquat-detection`: Levenshtein-distance analysis of MCP package names against known legitimate and malicious packages
- `dynamic-ssrf-probing`: Read-only SSRF vulnerability probing via MCP JSON-RPC protocol against internal/cloud metadata endpoints
- `report-formatting`: Terminal table, JSON, and SARIF output formats with severity-level classification

### Modified Capabilities
<!-- None — initial implementation -->

## Non-Goals

- Destructive pentesting or exploitation payloads (this is an auditor, not a pentest tool)
- Real-time config file watching or daemon mode (post-MVP)
- MCP server fuzzing with coverage-guided mutation (post-MVP)
- OAuth token scope analysis (post-MVP)
- GUI or web interface — CLI only

## Impact

- New repository: `mcp-audit` at `github.com/mostafaelataby-cheviron/mcp-audit`
- New Go module with zero external dependencies (stdlib + `golang.org/x/sync/errgroup`)
- Cross-compiled binaries for macOS (arm64/amd64) and Linux (arm64/amd64)
- No breaking changes (greenfield project)
