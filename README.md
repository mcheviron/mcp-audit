# mcp-audit

MCP ecosystem security auditor. Static config scanning + dynamic SSRF probing. Single Go binary.

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

## Development

```bash
just install   # Install golangci-lint, goimports
just check     # Full CI pipeline: fmt -> vet -> build -> test -> loc-check -> lint
just lint      # Run linters only
just test      # Run tests only
```

## How It Works

**Static analysis** discovers MCP server configs across 5 AI coding tools (Claude Desktop, Cursor, Windsurf, VS Code, Continue), parses server entries, and checks package names for typosquatting via Levenshtein distance.

**Dynamic probing** connects to discovered MCP servers, performs the MCP handshake, and issues read-only SSRF probes against internal/cloud metadata endpoints. Probes are safe: metadata endpoints only, 4KB response limit, 5s timeout, opt-in only.

## Contributing

1. Run `just check` — must pass clean.
2. Commit and push.
3. Tag releases with `git tag -a vX.Y.Z -m "Release vX.Y.Z" && git push origin vX.Y.Z`.

## CHANGELOG

Each release should include a changelog entry with the following format:

```
## v<VERSION> (<DATE>)

### Added
- <new feature>

### Changed
- <changed behavior>

### Fixed
- <bug fix>

### Security
- <security improvement>
```
