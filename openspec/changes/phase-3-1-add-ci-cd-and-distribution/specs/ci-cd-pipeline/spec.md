# ci-cd-pipeline Specification

## Purpose
Automated build, test, lint, release, and distribution pipeline via GitHub Actions.

## ADDED Requirements

### Requirement: CI pipeline on push and PR
The system SHALL run `just check` (fmt → vet → build → test → loc-check → lint) on every push and pull request to main.

#### Scenario: CI passes on clean commit
- **WHEN** a commit is pushed to any branch
- **THEN** GitHub Actions runs the full check pipeline and reports success/failure

### Requirement: Release workflow on tag
The system SHALL trigger a goreleaser workflow when a semver tag (v*.*.*) is pushed. goreleaser SHALL cross-compile for macOS (arm64/amd64) and Linux (arm64/amd64), generate SPDX SBOM, and sign binaries with cosign keyless signing.

#### Scenario: Tag triggers release
- **WHEN** a tag `v0.2.0` is pushed
- **THEN** goreleaser builds binaries, generates SBOM, signs, and creates a GitHub Release

### Requirement: Version injection via ldflags
The system SHALL inject git tag, commit hash, and build date into the binary via `-ldflags`. `--version` SHALL display all three values.

#### Scenario: Version from tagged build
- **WHEN** built from tag `v0.2.0`
- **THEN** `mcp-audit version` outputs `mcp-audit v0.2.0 (commit: abc1234, built: 2026-06-17T10:00:00Z)`

### Requirement: Shell completions
The system SHALL support `mcp-audit completion bash|zsh|fish` outputting shell completion scripts.

#### Scenario: Bash completion
- **WHEN** `mcp-audit completion bash` is run
- **THEN** a bash completion script is written to stdout
