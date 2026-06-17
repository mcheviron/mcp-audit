## Context

Zero built-in intelligence after commit `3fc3816`. User must supply all trust data. MCPShield has curated CVE DB, trusted scopes, community reports. Production tool needs baseline intelligence.

## Goals

Embed curated package lists at build time, `trust update` to fetch updates, `trust export/import` for sharing, opt-in findings upload, community DB repo, MCPShield DB compatibility.

## Decisions

### Embedded defaults via go:embed

`//go:embed default-trust.json` in `internal/intel/curated.go`. Contains known-safe packages (@anthropic/, @modelcontextprotocol/, @microsoft/, @google/ npm scopes) and known-malicious (placeholder — populated from community DB). Users can override with their own trust config.

### Update mechanism: GitHub Releases

`mcp-audit trust update` fetches `https://github.com/mcp-audit-db/releases/latest/download/trust.json`. Writes to `~/.config/mcp-audit/trust.json`. User is prompted before overwriting local changes if file differs from embedded default.

### Findings upload: one-way, anonymized

`mcp-audit upload` serializes findings without server names, URLs, or IPs. Only package names, finding types, and severity. User confirms before upload. Upload is HTTP POST to community DB API (or GitHub Issue with JSON body).

### MCPShield compatibility

Community DB uses same JSON schema as MCPShield's `data/vulndb.js` where possible — `{name, cve, cvss, affected_versions, description}` format. Enables cross-tool intelligence sharing.

## Risks

- **Embedded lists age** → Mitigation: `trust update` fetches fresh lists. Ship with creation date in embedded data. Warn if embedded data >90 days old.
- **Upload privacy** → Mitigation: show exact data being uploaded, require confirmation, document what is sent.
