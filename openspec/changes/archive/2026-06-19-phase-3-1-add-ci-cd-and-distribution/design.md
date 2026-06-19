## Context

PLAN.md Milestone 3 listed GitHub Actions release workflow, cross-compilation, and binary distribution. Never built. Tool currently installable only via `go install`. Version hardcoded as "v0.1.0".

## Goals

CI pipeline (test/lint/vet on push/PR), goreleaser release (macOS arm64/amd64, Linux arm64/amd64), SPDX SBOM, cosign keyless signing, Homebrew/Scoop/dpkg/rpm packages, shell completions, ldflags version injection, GitHub Action for CI scanning.

## Decisions

### goreleaser over manual build scripts

goreleaser handles cross-compilation, SBOM, signing, package managers, and changelogs in one config. Standard in Go ecosystem. Single `.goreleaser.yaml` covers all distribution.

### cosign keyless signing via GitHub OIDC

No long-lived signing keys to manage. GitHub Actions OIDC token authenticates to Sigstore. Signing happens in release workflow. Users verify with `cosign verify-blob --certificate-identity ...`.

### Shell completions: built into binary

`mcp-audit completion bash|zsh|fish` outputs completion script. goreleaser can package these. No separate completion files to maintain.

### GitHub Action: composite action

`mcp-audit-action` repo with `action.yml` that downloads mcp-audit binary and runs `mcp-audit static --format sarif`. SARIF uploads to GitHub Code Scanning.
