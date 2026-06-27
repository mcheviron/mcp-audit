## ADDED Requirements

### Requirement: Binary verification manifest

The system SHALL provide a `verify` subcommand that emits a deterministic JSON
manifest describing the binary's identity and embedded data versions. The
manifest SHALL include the binary's semver version, git commit hash, build
date, Go runtime version, SHA-256 hash of the embedded typo package list, and
SHA-256 hash of the embedded known-packages list. The manifest SHALL also
include the schema version for each output format (json, sarif). The manifest
SHALL be byte-identical across invocations of the same binary.

#### Scenario: Default JSON output

- **WHEN** the user runs `mcp-audit verify`
- **THEN** a JSON manifest is printed to stdout
- **AND** the manifest contains the keys: `version`, `commit`, `build_date`,
  `go_version`, `typo_list_sha256`, `package_list_sha256`, `schema_json`,
  `schema_sarif`
- **AND** all keys are present in every output
- **AND** no extra keys appear

#### Scenario: Deterministic output

- **WHEN** the user runs `mcp-audit verify` twice on the same binary
- **THEN** both invocations produce byte-identical stdout

#### Scenario: Text output

- **WHEN** the user runs `mcp-audit verify --text`
- **THEN** a human-readable text manifest is printed to stdout
- **AND** the text contains the binary version on the first line

#### Scenario: Piping into sha256sum

- **WHEN** the user runs `mcp-audit verify | sha256sum`
- **THEN** the command exits with code 0
- **AND** sha256sum prints a stable hash for the same binary

### Requirement: Verification exit code

The `verify` subcommand SHALL exit with code 0 on success. It SHALL exit with
non-zero only on internal errors (currently impossible since all data is
embedded at compile time).

#### Scenario: Successful verify

- **WHEN** the user runs `mcp-audit verify`
- **THEN** the exit code is 0
