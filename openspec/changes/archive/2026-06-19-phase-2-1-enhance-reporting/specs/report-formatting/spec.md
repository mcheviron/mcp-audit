# report-formatting Delta Specification

## ADDED Requirements

### Requirement: CWE taxonomy in SARIF
The system SHALL include a `taxa` section in SARIF output mapping rule IDs to CWE identifiers. Each `reportingDescriptor` SHALL reference the relevant OWASP MCP Top 10 category.

#### Scenario: SARIF with CWE mapping
- **WHEN** output format is SARIF
- **THEN** the output includes `taxa` entries for CWE-918 (SSRF), CWE-200 (Info Exposure), CWE-350 (Typosquat), CWE-506 (Malicious Code)
- **AND** each result's rule references a `reportingDescriptor` with CWE and OWASP MCP Top 10 help URI

### Requirement: JUnit XML output
The system SHALL support `--format junit` producing JUnit XML. Each finding SHALL become a `<testcase>`. CRITICAL/HIGH → `<failure>`, MEDIUM → `<error>`, LOW/INFO → `<skipped>`, PASS → passed testcase.

#### Scenario: JUnit output
- **WHEN** `--format junit` is set
- **THEN** output is valid JUnit XML with `<testsuite>` containing one `<testcase>` per finding

### Requirement: JSON metadata
The system SHALL include `tool`, `version`, `scan_time`, and `summary` fields in JSON output wrapping the findings array.

#### Scenario: JSON with metadata
- **WHEN** output format is JSON
- **THEN** the output includes top-level `tool`, `version`, `scan_time`, and `summary` fields

### Requirement: Table grouping
The system SHALL group table output by severity with headers between groups. A summary header SHALL display counts before the findings list.

#### Scenario: Table grouped by severity
- **WHEN** output format is table
- **THEN** findings are grouped under "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "PASS" headers with blank line between groups

### Requirement: Exit code granularity
The system SHALL exit with 0 (clean), 1 (CRITICAL found), 2 (HIGH found), 3 (MEDIUM found), 4 (scan error). LOW/INFO/PASS SHALL not affect exit code.

#### Scenario: Exit code 1 for CRITICAL
- **WHEN** any finding has CRITICAL severity
- **THEN** the process exits with code 1

#### Scenario: Exit code 0 for INFO only
- **WHEN** findings are only INFO and PASS
- **THEN** the process exits with code 0

## MODIFIED Requirements

### Requirement: SARIF output for CI integration
The system SHALL include PASS results in SARIF output as `note` level findings. Previously PASS results were excluded from SARIF entirely.

#### Scenario: PASS included in SARIF
- **WHEN** output format is SARIF and there are PASS findings
- **THEN** PASS findings appear as `note` level results with ruleId `mcp-audit/static-pass` or `mcp-audit/dynamic-pass`
