# package-distribution Specification

## Purpose
Homebrew, Scoop, dpkg, and rpm package generation for multi-platform distribution.

## Requirements

### Requirement: Homebrew tap
The system SHALL generate a Homebrew formula in goreleaser pointing to the GitHub release archive with SHA256 checksum.

#### Scenario: Brew install
- **WHEN** user runs `brew install mcp-audit`
- **THEN** the latest release binary is downloaded and installed

### Requirement: Binary checksums
The system SHALL publish a `checksums.txt` file with SHA256 hashes of all release artifacts.

#### Scenario: Checksum verification
- **WHEN** a user downloads a release binary
- **THEN** they can verify its SHA256 against the published checksums file

### Requirement: SBOM generation
The system SHALL generate an SPDX 2.3 SBOM per release listing all Go modules and versions.

#### Scenario: SBOM published
- **WHEN** a release is created
- **THEN** an `sbom.spdx.json` file is attached to the release
