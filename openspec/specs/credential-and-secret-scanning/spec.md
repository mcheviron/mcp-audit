# credential-and-secret-scanning Specification

## Purpose
Static analysis of MCP config files and server configuration for hardcoded credentials including API keys, tokens, connection strings, and private keys.

## Requirements

### Requirement: Raw config credential scanning
The system SHALL scan the raw bytes of each discovered config file with 16 credential detection regex patterns. Scanning SHALL run on the raw bytes regardless of whether JSON parsing succeeds, so credentials in malformed or unparseable configs are still detected. Any match SHALL be reported at CRITICAL severity with the credential type and file location. Credential values SHALL be redacted in output.

#### Scenario: AWS key detected in config
- **WHEN** a config file contains a string matching `AKIA[0-9A-Z]{16}`
- **THEN** a CRITICAL finding reports "AWS access key detected in <filepath>" with redacted value

#### Scenario: OpenAI key detected
- **WHEN** a config file contains a string matching `sk-[a-zA-Z0-9]{20,}`
- **THEN** a CRITICAL finding reports "OpenAI API key detected in <filepath>"

#### Scenario: GitHub token detected
- **WHEN** a config file contains `ghp_`, `gho_`, `ghu_`, `ghs_`, or `ghr_` followed by 20+ alphanumeric chars
- **THEN** a CRITICAL finding reports "GitHub token detected in <filepath>"

#### Scenario: Database URL with credentials
- **WHEN** a config file contains `postgres://user:pass@host/db` or similar database URL with embedded credentials
- **THEN** a CRITICAL finding reports "database connection string with credentials detected in <filepath>"

#### Scenario: PEM private key detected
- **WHEN** a config file contains `-----BEGIN RSA PRIVATE KEY-----` or `-----BEGIN EC PRIVATE KEY-----`
- **THEN** a CRITICAL finding reports "private key detected in <filepath>"

#### Scenario: No credentials found
- **WHEN** a config file contains no credential patterns
- **THEN** no credential finding is raised

### Requirement: Structured env value scanning
The system SHALL parse `env` blocks from MCP server configurations and scan each value for credential patterns. Detected credentials SHALL include the server name and env key in the finding.

#### Scenario: API key in env block
- **WHEN** a server config has `"env": {"API_KEY": "sk-abc123..."}`
- **THEN** a CRITICAL finding reports "credential in env var API_KEY for server <name>"

#### Scenario: Clean env values
- **WHEN** env values contain no credential patterns
- **THEN** no credential finding is raised for env values

### Requirement: Args credential scanning
The system SHALL scan command arguments for embedded credentials, particularly database URLs and connection strings passed as CLI arguments.

#### Scenario: Connection string in args
- **WHEN** a server config has `"args": ["--db", "postgres://user:pass@localhost/db"]`
- **THEN** a CRITICAL finding reports "credential in args for server <name>"

### Requirement: Header credential scanning
The system SHALL scan HTTP header values in server configurations for hardcoded Authorization tokens and API keys.

#### Scenario: Bearer token in headers
- **WHEN** a server config has `"headers": {"Authorization": "Bearer ya29.abc123..."}`
- **THEN** a CRITICAL finding reports "hardcoded Authorization header for server <name>"

### Requirement: Credential redaction in output
The system SHALL redact credential values in all findings. Redaction SHALL replace the credential substring with `[REDACTED]`. The credential type and location SHALL remain visible. The raw credential SHALL never appear in stdout, stderr, JSON output, or SARIF output.

#### Scenario: Redacted output
- **WHEN** a credential finding is written to any output format
- **THEN** the credential value is replaced with `[REDACTED]` and the finding text identifies only the credential type and location

### Requirement: Credential scanning toggle
The system SHALL support a `--no-secret-scan` flag to disable credential scanning. When disabled, no credential patterns are checked and no credential findings are reported.

#### Scenario: Secret scanning disabled
- **WHEN** `--no-secret-scan` is passed
- **THEN** no credential patterns are applied to config files
