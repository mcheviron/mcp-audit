## 1. Embedded intelligence

- [x] 1.1 Create `internal/intel/curated.go` with `//go:embed default-trust.json` embedding default trust config
- [x] 1.2 Populate default trust config with known-safe publishers (@anthropic/, @modelcontextprotocol/, @microsoft/, @google/, @vercel/, @cloudflare/) and known-safe packages
- [x] 1.3 Add `generated_at` timestamp and `version` field to embedded config
- [x] 1.4 Fall back to embedded defaults when no user config exists and no `--trust-config` flag

## 2. Trust config management

- [x] 2.1 Add `mcp-audit trust update` subcommand — fetch from GitHub releases, prompt if local differs
- [x] 2.2 Add `mcp-audit trust export` subcommand — output effective config to stdout
- [x] 2.3 Add `mcp-audit trust import <file>` subcommand — merge external config with local
- [x] 2.4 Warn if embedded data is >90 days old and suggest `trust update`

## 3. Findings upload

- [x] 3.1 Add `mcp-audit upload` subcommand — serialize findings, strip server names/URLs/IPs
- [x] 3.2 Display anonymized data and prompt for confirmation before upload
- [x] 3.3 POST to community DB API endpoint (or create GitHub Issue with JSON body)

## 4. Community DB

- [x] 4.1 Create `mcp-audit-db` GitHub repo with README, schema, and initial data
- [x] 4.2 Define JSON schema: `trusted.json`, `blocked.json`, `cve.json` with MCPShield-compatible format
- [x] 4.3 Add GitHub Actions workflow to validate schema and publish releases
- [x] 4.4 Add contribution guide for community submissions

## 5. Tests

- [x] 5.1 Test embedded defaults load when no user config exists
- [x] 5.2 Test user config overrides embedded defaults
- [x] 5.3 Test trust update fetch (mock HTTP server)
- [x] 5.4 Test trust export outputs correct merged config
- [x] 5.5 Test upload anonymization strips all PII
