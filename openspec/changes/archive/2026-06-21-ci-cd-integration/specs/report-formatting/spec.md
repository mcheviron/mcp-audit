# report-formatting Delta Spec

## ADDED Requirements

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
