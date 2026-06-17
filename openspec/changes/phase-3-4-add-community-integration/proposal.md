## Why

The tool's only package intelligence is user-supplied trust config JSON. Commit `3fc3816` removed embedded typosquat lists in favor of user-supplied config — the right architectural move, but it left zero built-in intelligence. MCPShield maintains a curated CVE database, trusted publisher scopes, and community-contributed vulnerability reports. A production tool should ship with baseline intelligence and support community contributions.

## What Changes

- Embed curated package intelligence: known-malicious packages, known-safe packages, trusted npm/pipx publishers
- Ship with default trust config at `~/.config/mcp-audit/trust.json` on first run (user can override)
- `mcp-audit trust update` — fetch latest curated lists from GitHub releases
- `mcp-audit trust export` — output current trust config with local additions
- `mcp-audit trust import` — merge external trust config with local
- Findings upload: `mcp-audit upload` (opt-in) to contribute anonymized findings to community DB
- Community DB: GitHub repo `mcp-audit-db` with curated `trusted.json`, `blocked.json`, `cve.json`
- Integration with MCPShield vuln DB format for cross-tool compatibility

## Capabilities

### New Capabilities

- `community-intelligence`: Curated package intelligence embedded at build time with update mechanism, findings contribution, and cross-tool database compatibility.

## Impact

- `internal/intel/` — new package: `curated.go` (embedded default lists), `update.go` (fetch from GitHub)
- `main.go` — `trust update|export|import`, `upload` subcommands
- `trust.json` — shipped default at `~/.config/mcp-audit/trust.json`
- New repo: `mcp-audit-db` — community vulnerability and package intelligence database
- `.github/workflows/intel-update.yml` — periodic curation updates

## Non-Goals

- Real-time threat feed (requires server infrastructure)
- Automated CVE assignment or disclosure
- Telemetry or tracking — upload is opt-in only, no automatic data collection
- Paid/proprietary intelligence feeds
