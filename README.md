# mcp-audit

MCP ecosystem security auditor. Static config scanning + dynamic SSRF probing. Single Go binary.

## Install

**go install**

```bash
go install github.com/mostafaelataby-cheviron/mcp-audit@latest
```

**Homebrew**

```bash
brew tap mostafaelataby-cheviron/tap
brew install mcp-audit
```

**Scoop (Windows)**

```powershell
scoop bucket add mostafaelataby-cheviron https://github.com/mostafaelataby-cheviron/scoop-bucket
scoop install mcp-audit
```

**dpkg (Debian/Ubuntu)**

```bash
gh release download --repo mostafaelataby-cheviron/mcp-audit --pattern '*.deb'
sudo dpkg -i mcp-audit_*.deb
```

**rpm (Fedora/RHEL)**

```bash
gh release download --repo mostafaelataby-cheviron/mcp-audit --pattern '*.rpm'
sudo rpm -i mcp-audit_*.rpm
```

**Download binary**

Prebuilt binaries for macOS (amd64, arm64) and Linux (amd64, arm64) are available on the [releases page](https://github.com/mostafaelataby-cheviron/mcp-audit/releases).

**Verify signature**

```bash
cosign verify-blob \
  --certificate-identity https://github.com/mostafaelataby-cheviron/mcp-audit/.github/workflows/release.yml@refs/tags/<version> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature mcp-audit_<version>_<os>_<arch>.tar.gz.sig \
  mcp-audit_<version>_<os>_<arch>.tar.gz
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

### Release process

1. Check that `just check` passes on `main`.
2. Update the changelog (see `CHANGELOG.md` template section at the end).
3. Tag a new release:
   ```bash
   git tag -a v0.2.0 -m "Release v0.2.0"
   git push origin v0.2.0
   ```
4. The [release workflow](.github/workflows/release.yml) builds and publishes binaries, packages, and SBOM.

### Versioning

Version is injected at build time via ldflags. To build with version info:

```bash
go build -ldflags "-X main.version=v0.2.0 -X main.commit=$(git rev-parse --short HEAD) -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" .
```

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
