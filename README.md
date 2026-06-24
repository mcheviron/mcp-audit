# mcp-audit

MCP ecosystem security auditor.

Discovers MCP server configs across 12 AI coding tools, scans for typosquatting, credential leaks, and CVEs, then probes servers for SSRF, prompt injection, and supply-chain risks.

## Install

```bash
go install github.com/mcheviron/mcp-audit/cmd/mcp-audit@latest
```

## Shell completions

```bash
# bash — add to ~/.bashrc or ~/.bash_profile
source <(mcp-audit completion bash)

# zsh — add to ~/.zshrc
source <(mcp-audit completion zsh)

# fish — add to ~/.config/fish/completions/
mcp-audit completion fish > ~/.config/fish/completions/mcp-audit.fish
```

## Usage

```bash
mcp-audit static              # Config-only scan (no network)
mcp-audit probe --dry-run     # Preview SSRF probes
mcp-audit probe               # Run SSRF probes
mcp-audit scan --format json  # Full audit, JSON output
mcp-audit scan --format sarif # SARIF for CI integration
mcp-audit scan --ci           # CI mode: SARIF + JSON summary + provenance
mcp-audit sbom                # Generate SBOM (CycloneDX / SPDX)
mcp-audit watch               # Watch configs and re-scan on changes
mcp-audit proxy --target URL  # Transparent MCP proxy with policy enforcement
mcp-audit trust update        # Update trusted package list from remote
mcp-audit upload              # Upload anonymized findings to community DB
```

## Example

```
$ mcp-audit static

SEVERITY  SERVER         FINDING
PASS      prospect       known legitimate package
PASS      filesystem     known legitimate package
INFO      mcp-srv-files  potential typosquat: "mcp-srv-files" is distance 2 from
                         known package "@modelcontextprotocol/server-filesystem"

1 INFO  2 PASS  —  3 servers scanned
```

## How It Works

### Static analysis

Discovers MCP server configs across 12 AI tools: Claude Desktop, Claude Code, Cursor, Windsurf, VS Code, Continue, OpenCode, Copilot CLI, Codex, Gemini, Cline/Roo, and Zed. Custom tools can be registered via `~/.config/mcp-audit/tools.json`.

Runs three checks per server:

- **Typosquat detection** — Levenshtein distance against known MCP packages (distance ≤ 2 triggers INFO, exact blocked-package matches trigger CRITICAL).
- **Credential scanning** — regex scan of config content, env vars, and headers for AWS keys, GCP tokens, private keys, and API tokens.
- **CVE scanning** — queries NVD and GitHub Advisory API for known vulnerabilities per package, with local caching.

### Dynamic probing

Connects to discovered servers via MCP handshake (stdio, SSE, or HTTP transport), then issues SSRF probes against internal and cloud metadata endpoints (AWS, GCP, Azure, OCI, OpenStack, loopback/private IPs). Uses GET/POST/PUT with header injection, redirect following (up to 5 hops), timing analysis, and entropy-based response classification.

Probe depth levels:

- **basic** — standard metadata endpoint probes
- **extended** — adds header injection and additional cloud providers
- **full** — adds DNS rebinding and callback listener for blind SSRF confirmation

### Security analysis

- **Tool schema analysis** — inspects tool descriptions for prompt injection patterns, embedded URLs, empty descriptions, and Base64-encoded payloads. Includes a 5-stage deobfuscation pipeline (Unicode tag stripping, BIDI override detection, zero-width character counting, Base64 decoding, confusable character lookup).
- **Heuristic risk scoring** — multi-factor weighted scoring across 5 dimensions (typosquat distance, CVE count, capability breadth, description quality, network exposure). Scores 0–100 per server.
- **Adversarial probing** — sends crafted prompts to text-accepting tools to detect system prompt leakage and role-switching injection (`--adversarial`).
- **Cross-server analysis** — detects tool shadowing (same-named tools across servers with different descriptions).
- **Blast radius** — BFS dependency chains from CVEs through affected servers, configs, tools, and credentials (`--blast-radius`).
- **Drift detection** — snapshots tool schemas across scans, flags changes between runs.
- **Compliance mapping** — maps findings to SOC 2, NIST AI RMF, OWASP LLM, MITRE ATLAS, and EU AI Act frameworks.

### Output

Formats: table (colorized TTY), JSON, SARIF, JUnit. CI mode adds provenance from GitHub environment variables and produces a JSON summary. Signed evidence bundles available via `--export-evidence`.
