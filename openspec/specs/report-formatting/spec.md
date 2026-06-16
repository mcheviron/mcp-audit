# report-formatting Specification

## Purpose
Table (colorized TTY), JSON, and SARIF v2.1.0 output with severity-anchored exit codes for CI gating.
## Requirements
### Requirement: Terminal table output (default)
The system SHALL output scan results as a formatted terminal table by default, with columns for severity, server name, and finding description.

#### Scenario: Default output format
- **WHEN** user runs `mcp-audit scan` with no format flag
- **THEN** results are displayed as an aligned text table with severity, server, and finding columns

#### Scenario: Color-coded severity
- **WHEN** output is to a TTY
- **THEN** CRITICAL findings are red, HIGH are yellow, MEDIUM are cyan, LOW are blue, INFO are dim, PASS are green

### Requirement: JSON output
The system SHALL support `--format json` producing structured output with an array of findings, each containing severity, server name, finding type, description, and raw probe data.

#### Scenario: JSON output for scripting
- **WHEN** user runs `mcp-audit scan --format json`
- **THEN** output is valid JSON on stdout, all human-readable text (banners, progress) goes to stderr

#### Scenario: JSON schema stability
- **WHEN** a finding is serialized to JSON
- **THEN** it SHALL include fields: `severity`, `server`, `type` (static/dynamic), `finding`, `detail` (optional, with probe response data)

### Requirement: SARIF output for CI integration
The system SHALL support `--format sarif` producing SARIF v2.1.0 compliant output suitable for GitHub Code Scanning and other SARIF-consuming tools.

#### Scenario: SARIF file written
- **WHEN** user runs `mcp-audit scan --format sarif --output results.sarif`
- **THEN** a valid SARIF v2.1.0 JSON file is written to the specified path

#### Scenario: SARIF severity mapping
- **WHEN** a CRITICAL finding is emitted in SARIF
- **THEN** it maps to SARIF severity `error`; HIGH maps to `error`; MEDIUM maps to `warning`; LOW and INFO map to `note`

### Requirement: Exit codes
The system SHALL exit with a non-zero exit code when CRITICAL or HIGH severity findings are present, enabling CI pipeline gating.

#### Scenario: Clean scan
- **WHEN** scan completes with zero CRITICAL or HIGH findings
- **THEN** exit code is 0

#### Scenario: Critical finding found
- **WHEN** scan reports at least one CRITICAL or HIGH finding
- **THEN** exit code is 1

#### Scenario: Scan error
- **WHEN** scanner encounters an unrecoverable error (e.g., no config files readable due to permissions)
- **THEN** exit code is 2, error details printed to stderr

### Requirement: Summary block
The system SHALL print a summary block after all findings showing: total servers scanned, findings per severity tier, and counts of static vs dynamic findings.

#### Scenario: Mixed results summary
- **WHEN** scan finds 2 CRITICAL, 1 HIGH, 0 MEDIUM, 1 INFO, and 4 PASS across 8 servers
- **THEN** the summary displays: "2 CRITICAL  1 HIGH  0 MEDIUM  1 INFO  4 PASS  —  8 servers scanned"

