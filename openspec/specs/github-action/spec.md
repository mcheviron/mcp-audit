# github-action Specification

## Purpose
Official GitHub Action that runs mcp-audit in CI, uploads SARIF to Code Scanning, and gates pull requests on severity thresholds.

## Requirements

### Requirement: Action definition
The system SHALL provide a composite GitHub Action at `action/action.yml` that runs `mcp-audit scan` with configurable inputs. The action SHALL be usable as `uses: mcp-audit/action@v1`.

#### Scenario: Action runs on pull request
- **WHEN** a GitHub Actions workflow references `uses: mcp-audit/action@v1`
- **THEN** the action downloads and runs the mcp-audit binary, producing scan results

### Requirement: Action inputs
The action SHALL accept inputs: `format` (default `sarif`), `severity-min` (default `LOW`), `trust-config`, `targets`, `probe-depth` (default `basic`), `no-cve-scan` (default `false`).

#### Scenario: Custom severity threshold
- **WHEN** the action is configured with `severity-min: HIGH`
- **THEN** only HIGH and CRITICAL findings cause the action to fail

#### Scenario: Custom probe targets
- **WHEN** the action is configured with `targets: "http://staging.internal:8080/"`
- **THEN** probes target the specified URLs instead of defaults

### Requirement: Action outputs
The action SHALL provide outputs: `critical-count`, `high-count`, `medium-count`, `low-count`, `sarif-file`.

#### Scenario: Output accessibility
- **WHEN** the action completes with findings
- **THEN** downstream steps can reference `${{ steps.audit.outputs.critical-count }}`

### Requirement: SARIF upload to Code Scanning
When findings with severity MEDIUM or above exist, the action SHALL upload the SARIF output to GitHub Code Scanning using `github/codeql-action/upload-sarif`.

#### Scenario: Findings trigger SARIF upload
- **WHEN** scan finds 2 HIGH and 1 MEDIUM findings
- **THEN** SARIF is uploaded and Code Scanning alerts are created on the repository

#### Scenario: No findings, no SARIF upload
- **WHEN** scan produces only PASS and INFO findings
- **THEN** the SARIF upload step is skipped

### Requirement: Action gating
The action SHALL fail the workflow (non-zero exit) when findings at or above the configured `severity-min` exist. The failure SHALL include a summary of findings in the step log.

#### Scenario: Gate blocks CRITICAL finding
- **WHEN** scan finds a CRITICAL finding and `severity-min` is `LOW`
- **THEN** the workflow step fails with exit code 1

#### Scenario: Gate passes with only INFO
- **WHEN** scan finds only INFO and PASS findings with `severity-min` set to `LOW`
- **THEN** the workflow step succeeds
