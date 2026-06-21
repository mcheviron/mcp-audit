# report-formatting Specification

## Purpose
Table (colorized TTY), JUnit XML, JSON, and SARIF v2.1.0 output with severity-anchored exit codes for CI gating, including CWE taxonomy metadata.
## Requirements
### Requirement: Terminal table output (default)
The system SHALL output scan results as a formatted terminal table by default, with columns for severity, server name, and finding description. The system SHALL propagate I/O errors from all write operations. If any `Fprintf` call to the output writer fails, the table writer SHALL return the error immediately.

#### Scenario: Default output format
- **WHEN** user runs `mcp-audit scan` with no format flag
- **THEN** results are displayed as an aligned text table with severity, server, and finding columns

#### Scenario: Color-coded severity
- **WHEN** output is to a TTY
- **THEN** CRITICAL findings are red, HIGH are yellow, MEDIUM are cyan, LOW are blue, INFO are dim, PASS are green

#### Scenario: Write error propagated
- **WHEN** the output writer returns an error during table formatting (e.g., broken pipe)
- **THEN** the table writer returns the error instead of silently discarding it

### Requirement: JSON output
The system SHALL support `--format json` producing structured output with an array of findings, each containing severity, server name, finding type, description, and raw probe data.

#### Scenario: JSON output for scripting
- **WHEN** user runs `mcp-audit scan --format json`
- **THEN** output is valid JSON on stdout, all human-readable text (banners, progress) goes to stderr

#### Scenario: JSON schema stability
- **WHEN** a finding is serialized to JSON
- **THEN** it SHALL include fields: `severity`, `server`, `type` (static/dynamic), `finding`, `detail` (optional, with probe response data), `remediation` (optional, severity-appropriate fix guidance)

### Requirement: JSON metadata
The system SHALL include `tool`, `version`, `scan_time`, and `summary` fields in JSON output wrapping the findings array.

#### Scenario: JSON with metadata
- **WHEN** output format is JSON
- **THEN** the output includes top-level `tool`, `version`, `scan_time`, and `summary` fields

### Requirement: SARIF output for CI integration
The system SHALL support `--format sarif` producing SARIF v2.1.0 compliant output suitable for GitHub Code Scanning and other SARIF-consuming tools.

#### Scenario: SARIF file written
- **WHEN** user runs `mcp-audit scan --format sarif --output results.sarif`
- **THEN** a valid SARIF v2.1.0 JSON file is written to the specified path

#### Scenario: SARIF severity mapping
- **WHEN** a CRITICAL finding is emitted in SARIF
- **THEN** it maps to SARIF severity `error`; HIGH maps to `error`; MEDIUM maps to `warning`; LOW and INFO map to `note`

#### Scenario: PASS included in SARIF
- **WHEN** output format is SARIF and there are PASS findings
- **THEN** PASS findings appear as `note` level results with ruleId `mcp-audit/static-pass` or `mcp-audit/dynamic-pass`

### Requirement: CWE taxonomy in SARIF
The system SHALL include a `taxa` section in SARIF output mapping rule IDs to CWE identifiers. Each `reportingDescriptor` SHALL reference the relevant OWASP MCP Top 10 category.

#### Scenario: SARIF with CWE mapping
- **WHEN** output format is SARIF
- **THEN** the output includes `taxa` entries for CWE-918 (SSRF), CWE-200 (Info Exposure), CWE-350 (Typosquat), CWE-506 (Malicious Code)
- **AND** each result's rule references a `reportingDescriptor` with CWE and OWASP MCP Top 10 help URI

### Requirement: JUnit XML output
The system SHALL support `--format junit` producing JUnit XML. Each finding SHALL become a `<testcase>`. CRITICAL/HIGH -> `<failure>`, MEDIUM -> `<error>`, LOW/INFO -> `<skipped>`, PASS -> passed testcase.

#### Scenario: JUnit output
- **WHEN** `--format junit` is set
- **THEN** output is valid JUnit XML with `<testsuite>` containing one `<testcase>` per finding

### Requirement: Table grouping
The system SHALL group table output by severity with headers between groups. A summary header SHALL display counts before the findings list.

#### Scenario: Table grouped by severity
- **WHEN** output format is table
- **THEN** findings are grouped under "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "PASS" headers with blank line between groups

### Requirement: Remediation guidance
The system SHALL include a remediation field in each finding providing actionable fix guidance. Remediation text SHALL be severity-appropriate and specific to the finding type.

#### Scenario: SSRF remediation
- **WHEN** a CRITICAL SSRF finding is reported
- **THEN** the Remediation field reads "Configure the MCP server to validate and sanitize all user-supplied URLs. Implement an allowlist of permitted outbound destinations. Never pass tool arguments directly to HTTP clients without validation."

#### Scenario: Typosquat remediation
- **WHEN** an INFO typosquat finding is reported
- **THEN** the Remediation field reads "Verify the package name is correct. Consider adding it to the trust config trusted list if legitimate, or the blocked list if malicious."

#### Scenario: PASS finding
- **WHEN** a PASS finding is reported
- **THEN** no remediation field is included (nothing to fix)

### Requirement: Exit code granularity
The system SHALL exit with 0 (clean), 1 (CRITICAL found), 2 (HIGH found), 3 (MEDIUM found), 4 (scan error). LOW/INFO/PASS SHALL not affect exit code.

#### Scenario: Exit code 1 for CRITICAL
- **WHEN** any finding has CRITICAL severity
- **THEN** the process exits with code 1

#### Scenario: Exit code 0 for INFO only
- **WHEN** findings are only INFO and PASS
- **THEN** the process exits with code 0

#### Scenario: Scan error
- **WHEN** scanner encounters an unrecoverable error (e.g., no config files readable due to permissions)
- **THEN** exit code is 4, error details printed to stderr

### Requirement: CI mode flag
The system SHALL accept a `--ci` CLI flag that optimizes output for CI environments. When `--ci` is set, the output format SHALL default to SARIF, a machine-readable JSON summary line SHALL be printed to stdout, and SARIF output SHALL include `versionControlProvenance` with repository URI, branch, and commit SHA from `GITHUB_*` environment variables.

#### Scenario: CI mode with GitHub env vars
- **WHEN** `--ci` is set and `GITHUB_REPOSITORY`, `GITHUB_REF`, `GITHUB_SHA` are present
- **THEN** SARIF output includes `versionControlProvenance` with those values

#### Scenario: CI summary line
- **WHEN** `--ci` is set and scan completes with 2 CRITICAL, 1 HIGH across 5 servers
- **THEN** stdout includes `{"critical":2,"high":1,"medium":0,"low":0,"info":0,"pass":0,"servers":5}`

#### Scenario: CI mode without GitHub env vars
- **WHEN** `--ci` is set but no `GITHUB_*` env vars are present
- **THEN** SARIF output omits `versionControlProvenance` but the summary line is still printed

### Requirement: SARIF version control provenance
SARIF output SHALL include a `versionControlProvenance` property in each `run` object when CI environment variables are available. The property SHALL contain `repositoryUri`, `branch`, and `revisionId`.

#### Scenario: SARIF with GitHub provenance
- **WHEN** `GITHUB_REPOSITORY=owner/repo`, `GITHUB_REF=refs/heads/main`, `GITHUB_SHA=abc123`
- **THEN** SARIF run includes `versionControlProvenance: {repositoryUri: "https://github.com/owner/repo", branch: "refs/heads/main", revisionId: "abc123"}`

### Requirement: Summary block
The system SHALL print a summary block after all findings showing: total servers scanned, findings per severity tier, and counts of static vs dynamic findings.

#### Scenario: Mixed results summary
- **WHEN** scan finds 2 CRITICAL, 1 HIGH, 0 MEDIUM, 1 INFO, and 4 PASS across 8 servers
- **THEN** the summary displays: "2 CRITICAL  1 HIGH  0 MEDIUM  1 INFO  4 PASS  —  8 servers scanned"

