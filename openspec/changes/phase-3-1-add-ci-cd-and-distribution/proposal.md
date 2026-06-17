## Why

The tool has no CI pipeline, no binary distribution beyond `go install`, no SBOM, no binary signing, and no package manager integration. A security tool distributed without integrity verification undermines its own purpose. PLAN.md Milestone 3 listed GitHub Actions release workflow and cross-compilation — these were never built.

## What Changes

- GitHub Actions CI: test, lint, vet on push/PR; release workflow with goreleaser on tag
- goreleaser config: cross-compile for macOS (arm64/amd64) and Linux (arm64/amd64)
- SBOM generation: SPDX 2.3 SBOM per release via `go version -m` + goreleaser
- Binary signing: cosign keyless signing via GitHub Actions OIDC
- Homebrew tap, Scoop bucket, and `dpkg`/`rpm` package generation via goreleaser
- Shell completions: bash, zsh, fish via `--completion` flag
- `--version` flag with git tag injection via ldflags
- GitHub Action for running mcp-audit in CI repos: `mcp-audit-action`

## Capabilities

### New Capabilities

- `ci-cd-pipeline`: Automated build, test, lint, release, and distribution pipeline
- `package-distribution`: Homebrew, Scoop, dpkg, and rpm package generation

## Impact

- `.github/workflows/ci.yml` — test, lint, vet on push/PR
- `.github/workflows/release.yml` — goreleaser on tag
- `.goreleaser.yaml` — cross-compile, SBOM, signing, package managers
- `main.go` — `--completion` flag, ldflags version injection
- `README.md` — install instructions for each distribution method
- New repo: `mcp-audit-action` — GitHub Action for CI scanning

## Non-Goals

- Docker image distribution (Go binary is static, no container needed)
- Windows MSI installer (can add later)
- Snap/Flatpak distribution
- Automated Homebrew formula submission (manual PR to homebrew-core)
