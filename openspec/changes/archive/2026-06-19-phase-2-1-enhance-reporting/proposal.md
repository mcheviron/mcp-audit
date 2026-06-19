## Why

SARIF output drops PASS results (lossy for CI), has no CWE/CVE taxonomy mapping, and doesn't reference OWASP MCP Top 10. JSON output has no version or metadata fields. Table output has no grouping or summary headers. No JUnit output for test-runner integration. No trend comparison between runs. A production security tool must produce standards-compliant, machine-consumable reports that integrate with security pipelines.

## What Changes

- SARIF: include PASS results as `note` level, add `taxa` section with CWE mappings (CWE-918 SSRF, CWE-200 Info Exposure, CWE-506 Malicious Code, CWE-350 Typosquat), add `reportingDescriptor` for each rule with OWASP MCP Top 10 references
- JUnit XML output: `--format junit` for CI test-runner integration
- JSON: add `version`, `scan_time`, `tool` metadata fields, include summary counts
- Table: group by severity, add summary header with counts, `--no-color` support
- Finding dedup in reports (see harden-engineering-foundations proposal)
- `--summary-only` flag to print only summary line
- Exit code granularity: 0=clean, 1=CRITICAL found, 2=HIGH found, 3=MEDIUM, 4=scan error

## Capabilities

### Modified Capabilities

- `report-formatting`: Extend SARIF with CWE taxonomy and OWASP references, add JUnit output format, add JSON metadata fields, add table grouping, add exit code granularity.

## Impact

- `internal/report/sarif.go` — taxa section, CWE mappings, PASS inclusion
- `internal/report/format.go` — JUnit writer, JSON metadata, table grouping, exit codes
- `main.go` — `--summary-only` flag, updated exit code mapping
- New file: `internal/report/junit.go`

## Non-Goals

- HTML report output
- PDF report generation
- Interactive/terminal UI report browsing
- Historical report storage or comparison (separate proposal)
