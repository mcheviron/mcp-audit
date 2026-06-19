# community-intelligence Specification

## Purpose
Curated package intelligence embedded at build time with update mechanism, findings contribution, and cross-tool database compatibility.

## ADDED Requirements

### Requirement: Embedded default trust config
The system SHALL embed a default trust config at build time containing known-safe npm/pipx publishers and known-malicious package names. The embedded config SHALL include a `generated_at` timestamp. If no user trust config exists and no `--trust-config` is passed, the embedded defaults SHALL be used.

#### Scenario: Embedded defaults used
- **WHEN** no user trust config exists and no `--trust-config` flag is set
- **THEN** the embedded default trust config is loaded

#### Scenario: User config overrides embedded
- **WHEN** `--trust-config ./my-trust.json` is passed
- **THEN** the user's config is used instead of embedded defaults

### Requirement: Trust config update
The system SHALL support `mcp-audit trust update` to fetch the latest curated trust config from the community DB GitHub releases. The update SHALL prompt before overwriting user-modified local configs.

#### Scenario: Update fetches latest
- **WHEN** `mcp-audit trust update` is run
- **THEN** the latest trust config is downloaded and written to `~/.config/mcp-audit/trust.json`

#### Scenario: Update preserves local changes
- **WHEN** the local trust config differs from the embedded default and update is run
- **THEN** the user is prompted before overwriting

### Requirement: Trust config export and import
The system SHALL support `mcp-audit trust export` to output the current trust config and `mcp-audit trust import <file>` to merge an external config.

#### Scenario: Export current config
- **WHEN** `mcp-audit trust export` is run
- **THEN** the current effective trust config (embedded + user overrides) is written to stdout

### Requirement: Opt-in findings upload
The system SHALL support `mcp-audit upload` to contribute anonymized findings to the community database. Upload SHALL be opt-in with explicit user confirmation. Server names, URLs, and IPs SHALL be stripped before upload.

#### Scenario: Upload with confirmation
- **WHEN** `mcp-audit upload` is run
- **THEN** the anonymized data to be uploaded is displayed and the user is prompted to confirm

### Requirement: MCPShield database compatibility
The community DB SHALL use a JSON schema compatible with MCPShield's vuln database format: `{name, cve, cvss, affected_versions, description}` for vulnerabilities.

#### Scenario: Cross-tool data exchange
- **WHEN** a vulnerability is added to the community DB
- **THEN** it can be consumed by MCPShield and vice versa
