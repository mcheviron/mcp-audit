## 1. CI pipeline

- [ ] 1.1 Create `.github/workflows/ci.yml` — run `just check` on push/PR to main
- [ ] 1.2 Add Go version matrix (1.26, stable) to CI
- [ ] 1.3 Add lint step with golangci-lint and loc-check

## 2. goreleaser

- [ ] 2.1 Create `.goreleaser.yaml` with cross-compile targets: darwin/amd64, darwin/arm64, linux/amd64, linux/arm64
- [ ] 2.2 Configure SPDX SBOM generation in goreleaser
- [ ] 2.3 Configure cosign keyless signing in goreleaser
- [ ] 2.4 Configure Homebrew tap, Scoop bucket, dpkg, and rpm generation
- [ ] 2.5 Create `.github/workflows/release.yml` — goreleaser on semver tag

## 3. Version injection

- [ ] 3.1 Add `version`, `commit`, `date` variables in `main.go` with ldflags defaults
- [ ] 3.2 Update `version` subcommand to print version, commit, and build date
- [ ] 3.3 Add ldflags to goreleaser build configuration

## 4. Shell completions

- [ ] 4.1 Add `completion` subcommand with bash, zsh, fish flags
- [ ] 4.2 Generate completions for all flags and subcommands
- [ ] 4.3 Package completions in goreleaser (or document redirection)

## 5. GitHub Action

- [ ] 5.1 Create `mcp-audit-action` repo with `action.yml`
- [ ] 5.2 Action downloads mcp-audit binary and runs static scan with SARIF output
- [ ] 5.3 Action uploads SARIF to GitHub Code Scanning

## 6. Documentation

- [ ] 6.1 Update README.md with install instructions for Homebrew, Scoop, dpkg, rpm, go install
- [ ] 6.2 Add contributing guide with release process
- [ ] 6.3 Add changelog template
