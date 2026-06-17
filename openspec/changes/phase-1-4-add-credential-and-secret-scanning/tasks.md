## 1. Credential pattern library

- [ ] 1.1 Expand `redactPatterns` in `analysis.go` to 16 patterns: AWS, GCP, OpenAI, GitHub (5 types), GitLab, Slack (3 types), JWT, PEM, database URLs (4 types), generic API keys
- [ ] 1.2 Add `credentialPatterns` as detection patterns (same regex, different purpose from redaction)
- [ ] 1.3 Ensure patterns have minimum length thresholds to reduce false positives

## 2. Raw config scanning

- [ ] 2.1 Implement `scanRawConfig(data []byte, path string) []Result` — apply all 16 patterns to raw bytes
- [ ] 2.2 Call `scanRawConfig` from `config.Discover()` before parsing each file
- [ ] 2.3 Report findings with file path and credential type, redacting values

## 3. Structured field extraction

- [ ] 3.1 Add `Env map[string]string` and `Headers map[string]string` to `config.ServerEntry`
- [ ] 3.2 Parse `env` and `headers` blocks in `parseMcpServers`, `parseContinue`, and `parseOpenCode`
- [ ] 3.3 Handle mixed env value types (string, number, bool) — coerce to string for scanning

## 4. Env, args, and header scanning

- [ ] 4.1 Implement `scanEnvValues(env map[string]string, serverName string) []Result` — scan each env value
- [ ] 4.2 Implement `scanArgs(args []string, serverName string) []Result` — join and scan for DB URLs
- [ ] 4.3 Implement `scanHeaders(headers map[string]string, serverName string) []Result` — scan for Authorization tokens
- [ ] 4.4 Call structured scanners from `checkTyposquat` or a new `checkCredentials` function in static.go

## 5. CLI integration

- [ ] 5.1 Add `--no-secret-scan` flag to `main.go`
- [ ] 5.2 Thread flag through `Scanner` struct as `NoSecretScan bool`
- [ ] 5.3 Guard all credential scanning behind this flag (default: enabled)

## 6. Tests

- [ ] 6.1 Test each of 16 credential patterns with positive and negative cases
- [ ] 6.2 Test credential detection in raw config, env values, args, and headers
- [ ] 6.3 Test redaction: verify raw values never appear in finding output
- [ ] 6.4 Test `--no-secret-scan` suppresses all credential findings
- [ ] 6.5 Test config files with no credentials produce no false findings
