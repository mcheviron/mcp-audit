# MCP Audit — Plan

Security auditor CLI for the MCP (Model Context Protocol) ecosystem. Static config scanning + dynamic SSRF probing. Single Go binary.

## Why

18-37% of open-source MCP servers have SSRF vulnerabilities (confirmed across 3 independent studies, 7,500+ servers). MCPShield exists (Rust, 1.6k stars) but only does static config analysis. No tool does runtime SSRF probing. This fills that gap — in Go, zero dependencies, for the Go MCP ecosystem.

## Architecture

```
mcp-audit (single binary)
│
├── cmd/mcp-audit/          # CLI entry point (cobra)
│   ├── scan     — full audit (static + dynamic)
│   ├── static   — config-only scan
│   ├── probe    — dynamic SSRF probe only
│   └── version  — version info
│
├── internal/
│   ├── scanner/
│   │   ├── static.go        # Config file scanner
│   │   │   └── Discovers MCP server configs across 5 AI tools:
│   │   │       • Claude Desktop  (~/Library/Application Support/Claude/claude_desktop_config.json)
│   │   │       • Cursor          (~/.cursor/mcp.json)
│   │   │       • Windsurf        (~/.codeium/windsurf/mcp_config.json)
│   │   │       • VS Code         (~/.vscode/mcp.json, .vscode/mcp.json in workspace)
│   │   │       • Continue        (~/.continue/config.json)
│   │   │   └── Parses each config, extracts MCP server endpoints + metadata
│   │   │
│   │   ├── dynamic.go        # SSRF prober
│   │   │   └── For each discovered MCP server:
│   │   │       • Connect via MCP JSON-RPC (initialize handshake)
│   │   │       • Issue crafted tool calls with SSRF payload URLs
│   │   │       • Check responses for leaked internal data
│   │   │       • Follow redirects, detect open redirect chains
│   │   │   └── Probe targets:
│   │   │       • 127.0.0.1 / localhost
│   │   │       • 169.254.169.254 (AWS/cloud metadata)
│   │   │       • metadata.google.internal (GCP)
│   │   │       • [::1] (IPv6 loopback)
│   │   │       • 0.0.0.0
│   │   │       • Private ranges (10.x, 172.16-31.x, 192.168.x)
│   │   │
│   │   └── typosquat.go      # Package name analysis
│   │       └── Levenshtein distance against:
│   │           • Known legitimate MCP packages (curated list)
│   │           • Known malicious packages (from MCPShield DB, community reports)
│   │           • Flags packages within edit distance ≤ 2
│   │
│   ├── mcp/
│   │   ├── protocol.go       # MCP JSON-RPC client (minimal)
│   │   │   └── initialize, tools/list, tools/call messages
│   │   ├── transport.go      # HTTP + stdio transport
│   │   │   └── Streamable HTTP (2024-11-05 spec) + stdio subprocess
│   │   └── sse.go            # SSE transport (legacy, pre-2024-11-05)
│   │
│   ├── config/
│   │   ├── discover.go       # Cross-platform config file discovery
│   │   ├── claude.go         # Claude Desktop config parser
│   │   ├── cursor.go         # Cursor config parser
│   │   ├── windsurf.go       # Windsurf config parser
│   │   ├── vscode.go         # VS Code config parser
│   │   └── continue.go       # Continue config parser
│   │
│   └── report/
│       ├── format.go         # Report struct + formatters
│       ├── json.go           # JSON output
│       ├── table.go          # Terminal table output (text/tabwriter)
│       └── sarif.go          # SARIF output (for CI integration)
│
├── pkg/
│   └── levenshtein/
│       └── distance.go       # Levenshtein distance (no external dep)
│
├── go.mod
├── go.sum
├── main.go                   # Entry point
├── PLAN.md                   # This file
└── README.md
```

## Dependencies

Zero external dependencies for MVP. Standard library covers everything:

| Need | Package |
|------|---------|
| CLI | `flag` (MVP) → `cobra` (v1) |
| HTTP client | `net/http` |
| JSON | `encoding/json` |
| Tables | `text/tabwriter` |
| File walking | `os`, `path/filepath` |
| Concurrency | `sync`, `sync/errgroup` (Go 1.22+) |
| Testing | `testing`, `net/http/httptest` |

One exception: `golang.org/x/sync/errgroup` for bounded concurrency on SSRF probes.

## Probe Safety

SSRF probing is inherently dangerous — we're making requests that could hit internal services. Safety measures:

1. **Read-only by design** — never send destructive payloads (DELETE, POST with body to internal endpoints)
2. **Metadata-only probes** — request metadata endpoints (`/latest/meta-data/`), not service APIs
3. **Response truncation** — read max 4KB per response, don't stream
4. **Timeout** — 5s per probe, 30s total probe phase
5. **Rate limiting** — max 10 concurrent probes, 100ms delay between probes to same host
6. **Opt-in dynamic** — `mcp-audit probe` requires explicit flag; `mcp-audit scan` prompts for confirmation
7. **Allowlist/blocklist** — `--allow-hosts`, `--block-hosts` flags for probe targets
8. **Dry-run mode** — `--dry-run` prints what would be probed without making requests

## Severity Levels

| Level | Criteria |
|-------|----------|
| **CRITICAL** | Server returns cloud metadata (AWS keys, GCP tokens) or internal service data |
| **HIGH** | Server follows redirect to internal IP, or returns internal HTTP response |
| **MEDIUM** | Server connects to internal IP (timeout/refused — firewall may have blocked) |
| **LOW** | Open redirect detected (no internal target reached) |
| **INFO** | Package name is typosquat (Levenshtein ≤ 2 from known package) |
| **PASS** | No issues found |

## MVP Milestones

### Milestone 1: Static Scanner (week 1)
- [ ] Config discovery for 5 AI tools (Claude Desktop, Cursor, Windsurf, VS Code, Continue)
- [ ] Parse configs, extract MCP server endpoints + package names
- [ ] Typosquat detection with Levenshtein distance
- [ ] Table + JSON output
- [ ] Tests with fixture configs

### Milestone 2: Dynamic Prober (week 2)
- [ ] Minimal MCP JSON-RPC client (initialize + tools/list)
- [ ] SSRF probe payloads (all target IPs)
- [ ] Response analysis (did we get metadata back?)
- [ ] Redirect following with internal-IP detection
- [ ] Safety controls (rate limit, timeout, dry-run)
- [ ] Integration tests with mock MCP server

### Milestone 3: Polish (week 3)
- [ ] SARIF output for CI integration
- [ ] `--dry-run`, `--allow-hosts`, `--block-hosts` flags
- [ ] Colored terminal output
- [ ] README with install instructions, usage examples, screenshot
- [ ] GitHub Actions release workflow (goreleaser)
- [ ] Cross-compile for macOS (arm64, amd64), Linux (arm64, amd64)

## Example Output

```
$ mcp-audit scan

  MCP Audit v0.1.0
  Scanning 5 config locations...

  Found 8 MCP servers across 3 config files.

  ─── Static Analysis ───────────────────────────────────
  SEVERITY   SERVER              FINDING
  INFO       mcp-server-filesys  Package "mcp-server-filesystem" is typosquat of "mcp-server-filesys"
                                 (Levenshtein distance: 2)
  PASS       prospect            No issues found
  PASS       glanceable-mcp      No issues found

  ─── Dynamic SSRF Probe ────────────────────────────────
  SEVERITY   SERVER              FINDING
  CRITICAL   mcp-server-utils    Returns AWS metadata: iam/security-credentials/admin
                                 GET http://169.254.169.254/latest/meta-data/ → 200 OK
  HIGH       mcp-server-fetcher  Follows redirect to internal IP
                                 GET https://evil.com/redirect → 302 → http://192.168.1.1/admin
  MEDIUM     mcp-server-data     Connection to metadata endpoint refused (firewall likely)
                                 GET http://169.254.169.254/ → connection refused
  PASS       prospect            No SSRF vulnerabilities detected

  ─── Summary ───────────────────────────────────────────
  1 CRITICAL  2 HIGH  0 MEDIUM  1 LOW  4 PASS
  Static: 8 scanned, 1 suspicious
  Dynamic: 4 probed, 3 vulnerable
```

## Design Decisions

1. **Go over Rust** — I/O-bound problem, goroutines simpler than async Rust, zero-dependency stdlib, MCPShield already owns Rust mindshare
2. **Read-only probing** — no destructive payloads, metadata endpoints only. This is an auditor, not a pentest tool
3. **Opt-in dynamic** — static scan runs by default; dynamic probing requires explicit `probe` subcommand or `--probe` flag with confirmation
4. **CodeCrafters ethos** — build MCP protocol client from scratch (not using MCP SDK), implement Levenshtein by hand, minimal dependencies. Understand every line
5. **Single binary** — `go build` produces one file. No runtime, no Python, no Node. Drop it in PATH, done

## Post-MVP Ideas

- Config file watching (filesystem notify, re-scan on change)
- MCP server fuzzing (coverage-guided tool input mutation)
- GitHub Action for CI (scan MCP configs in PRs)
- Community vulnerability database (contribute findings back)
- MCP proxy mode (sit between client and server, audit all traffic)
- OAuth token scope analysis for MCP servers
