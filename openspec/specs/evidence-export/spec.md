# evidence-export Specification

## Purpose
Export tamper-evident evidence bundles with HMAC-SHA256 chained integrity verification for audit and compliance purposes.

## Requirements

### Requirement: Signed evidence bundle export
The system SHALL support `--export-evidence <path>` flag producing a tamper-evident JSON bundle. Each bundle SHALL contain: scan timestamp, tool version, scan findings, blast-radius chains (if computed), compliance mappings, and an HMAC-SHA256 chain linking all entries. The HMAC key SHALL default to a random per-session value written to `<evidence-path>.key` with `0600` permissions; it SHALL be overridable via `--evidence-key <hex>`.

#### Scenario: Evidence bundle written
- **WHEN** `--export-evidence evidence.json` is set and a scan completes
- **THEN** the file `evidence.json` contains a JSON object with `scan_metadata`, `findings`, `hmac_chain`, and `chain_valid` fields

#### Scenario: HMAC chain verifiable
- **WHEN** the evidence bundle is loaded and HMAC values are recomputed with the same key
- **THEN** all entries verify with `chain_valid: true`

### Requirement: Evidence format versioning
The system SHALL include a `format_version` field in the evidence bundle (initial value `"1.0"`). Consumers SHALL reject bundles with unsupported versions.

#### Scenario: Version field present
- **WHEN** an evidence bundle is generated
- **THEN** it includes `"format_version": "1.0"`
