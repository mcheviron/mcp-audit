## MODIFIED Requirements

### Requirement: Opt-in findings upload
The system SHALL support `mcp-audit upload` to contribute anonymized findings to the community database. Upload SHALL be opt-in with explicit user confirmation. Server names, URLs, and IPs SHALL be stripped from BOTH the `Finding` and `Detail` fields before upload. The word-level redaction SHALL check against an expanded set of TLDs and hostname patterns including `.svc`, `.cluster.local`, `.corp`, `.lan`, `.lab`, `.test`, `.internal`, and `.localhost`.

#### Scenario: Upload with confirmation
- **WHEN** `mcp-audit upload` is run
- **THEN** the anonymized data to be uploaded is displayed and the user is prompted to confirm

#### Scenario: Finding field redacted
- **WHEN** a scanner finding contains an internal IP in the finding text (e.g., "tool fetch probed http://10.0.0.1/")
- **THEN** the IP is replaced with `[REDACTED]` in the uploaded Finding field

#### Scenario: Hostname in finding redacted
- **WHEN** a finding text contains an internal hostname (e.g., "response from api.internal.corp:8080")
- **THEN** the hostname is replaced with `[REDACTED]` in the uploaded Finding field

#### Scenario: Kubernetes cluster hostname redacted
- **WHEN** a finding text contains `metrics.svc.cluster.local`
- **THEN** the hostname is replaced with `[REDACTED]`

### Requirement: Trust config update
The system SHALL support `mcp-audit trust update` to fetch the latest curated trust config from the community DB GitHub releases. The update SHALL verify the SHA256 checksum of `trust.json` against `trust.json.sha256` from the same release. If the checksum file is present and verification fails, the update SHALL abort with an error. If the checksum file is absent, the update SHALL print a warning and proceed. The update SHALL prompt before overwriting user-modified local configs.

#### Scenario: Update fetches and verifies latest
- **WHEN** `mcp-audit trust update` is run and `trust.json.sha256` is available
- **THEN** the SHA256 of the downloaded `trust.json` is verified against the checksum file before writing to `~/.config/mcp-audit/trust.json`

#### Scenario: Checksum verification failure
- **WHEN** the downloaded `trust.json` does not match the checksum in `trust.json.sha256`
- **THEN** the update is aborted with an error and the local trust config is not modified

#### Scenario: Checksum file absent
- **WHEN** `trust.json.sha256` is not present in the GitHub release
- **THEN** a warning is printed and the update proceeds without verification

#### Scenario: Update preserves local changes
- **WHEN** the local trust config differs from the default and update is run
- **THEN** the user is prompted before overwriting
