## Why

MCP config files frequently contain secrets in plaintext: API keys in `env` blocks, database connection strings in `args`, OAuth tokens in headers. The current tool only scans probe response bodies for credential patterns — it never inspects the config files it discovers. MCPShield maintains 16 credential detection patterns and a dedicated `scanEnvValues()` function. OWASP MCP Top 10 classifies credential retrieval via prompt injection, compromised context, or debug traces as MCP01:2025. A security auditor that can't find hardcoded credentials in the very configs it parses is missing the most obvious vulnerability.

## What Changes

- Scan all discovered MCP config JSON for credential patterns before parsing server entries
- Scan `env` blocks in server configs for API keys, tokens, and database URLs
- Scan `args` arrays for embedded credentials (connection strings, tokens passed as CLI args)
- Scan `headers` blocks for hardcoded Authorization values
- 16+ credential patterns: AWS AKIA keys, OpenAI keys, GitHub/GitLab tokens, Slack tokens, generic API key patterns, database connection strings, JWT tokens, PEM private keys
- CRITICAL severity for any detected credential
- Redact credential values in output (already implemented for response bodies, reuse patterns)
- `--no-secret-scan` flag to disable (default: enabled)

## Capabilities

### New Capabilities

- `credential-and-secret-scanning`: Static analysis of MCP config files and server configuration for hardcoded credentials including API keys, tokens, connection strings, and private keys.

### Modified Capabilities

- `static-config-scanning`: Extend config parsing to extract and scan env vars, headers, and args for credential patterns before surfacing parsed server entries.

## Impact

- `internal/secrets/` — new package: 16 credential detection regex patterns and `ScanRaw`/`ScanEnv`/`ScanArgs`/`ScanHeaders` functions returning `Finding` values (single source of truth for patterns)
- `internal/scanner/credentials.go` — new `checkCredentials` orchestrates raw + structured scanning, converts `secrets.Finding` to `scanner.Result` at CRITICAL severity
- `internal/config/discover.go` — preserve raw config bytes on `Config.Raw`
- `internal/config/parser.go` — extract `env` and `headers` blocks from server entries into `ServerEntry` fields, coercing mixed value types to strings
- `internal/config/types.go` — `ServerEntry` gains `Env map[string]string`, `Headers map[string]string`; `Config` gains `Raw []byte`
- `main.go` — `--no-secret-scan` flag

## Non-Goals

- Entropy-based secret detection (too many false positives for config files)
- Scanning files outside discovered config paths (not a general secret scanner)
- Git history scanning for leaked credentials
- Real-time secret scanning on config changes (daemon mode, separate proposal)
