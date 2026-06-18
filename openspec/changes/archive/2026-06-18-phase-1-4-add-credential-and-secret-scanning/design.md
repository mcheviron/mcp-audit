## Context

MCP config files are JSON documents that frequently contain secrets. Claude Desktop config allows `env` blocks and `headers` blocks per server. VS Code and Cursor configs allow arbitrary JSON fields. The current parser extracts only `command`, `args`, and `url` — silently discarding `env`, `headers`, and other fields that may contain credentials.

Current credential detection: `analysis.go:24-29` defines `redactPatterns` for response body redaction. These patterns exist but are only applied post-probe, not during static config scanning. The config discovery phase in `discover.go` reads raw config bytes but never scans them for secrets.

## Goals / Non-Goals

**Goals:**
- Scan raw config JSON bytes for 16+ credential patterns before parsing
- Scan `env` values for API keys, tokens, database URLs
- Scan `args` arrays for embedded credentials
- Scan `headers` values for hardcoded Authorization
- CRITICAL severity for any detected credential
- Redact credential values in findings output
- Reuse existing `redactPatterns` from analysis.go, expand to 16 patterns

**Non-Goals:**
- Entropy-based detection (high FP rate)
- General filesystem secret scanning (only discovered config files)
- Git history scanning
- Real-time file watching for new secrets

## Decisions

### Pattern set: 16 regex patterns

Expand from current 4 redact patterns to 16 detection patterns covering:
- AWS AKIA keys (existing)
- GCP OAuth tokens (existing)
- OpenAI API keys (`sk-` prefix)
- GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`)
- GitLab tokens (`glpat-`)
- Slack tokens (`xoxb-`, `xoxp-`, `xoxa-`)
- Generic Bearer tokens in Authorization headers
- Database URLs (`postgres://`, `mysql://`, `mongodb://`, `redis://` with credentials)
- JWT tokens (eyJ header pattern with signature)
- PEM private keys (existing, expand to detect in config values)
- Generic API key patterns (long alphanumeric strings in `key`, `token`, `secret` named fields)

### Scan points: three phases

1. **Raw config scan**: `config.Discover()` preserves the raw bytes of each config file on `Config.Raw`. `scanner.checkCredentials` regex-scans those raw bytes for any credential pattern, running before the parse-error check so credentials in malformed/unparseable configs are still caught. Catch credentials in unexpected JSON locations.
2. **Structured env scan**: after parsing, iterate `env` map values through patterns.
3. **Args scan**: join args array, scan for database URLs and connection strings.

### Package layout

Credential patterns and scan functions live in a new `internal/secrets` package (single source of truth for the 16 patterns). `config` stores raw bytes only and does not import `secrets`; `scanner` owns all credential scanning and result construction, calling `secrets.ScanRaw`/`ScanEnv`/`ScanArgs`/`ScanHeaders` and converting `secrets.Finding` into `scanner.Result`. This keeps `config` a pure data/discovery layer and avoids a `config`↔`scanner` import cycle.

### Redaction in output

Credential values are never placed in finding text. Each finding carries only the credential type and location (e.g. "AWS access key detected in <filepath>", "OpenAI API key in env var API_KEY for server <name>"). The raw secret does not appear in stdout, stderr, JSON, or SARIF output.

### Integration with trust config

Credential scanning runs regardless of trust config. It's always-on (unless `--no-secret-scan`). This is a safety baseline, not a policy decision.

## Risks / Trade-offs

- **False positives on non-secret strings** → Pattern `sk-` (OpenAI) matches `sk-skip-validation`. Mitigation: require minimum length (20+ chars for API key patterns).
- **Performance on large configs** → 16 regex patterns × many config files. Mitigation: config files are typically <100KB. Regex scanning is O(n×p) where p=16 — negligible.
- **Config files outside standard paths** → Only scanning discovered configs, not arbitrary files. Mitigation: documented limitation. Users with non-standard configs use `--trust-config` pattern.

## Open Questions

- Should we also scan environment variables of the running process? (the audit tool's own env, not the scanned configs)
- Should credential findings include a SHA-256 hash of the secret for dedup without exposing the value?
