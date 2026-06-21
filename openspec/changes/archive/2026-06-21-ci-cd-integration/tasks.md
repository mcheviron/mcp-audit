## 1. CI mode flag

- [x] 1.1 Add `--ci` flag to `parseFlags()` in `cmd/mcp-audit/main.go`
- [x] 1.2 When `--ci` is set: force SARIF output, print JSON summary to stdout, set CI context
- [x] 1.3 Read `GITHUB_REPOSITORY`, `GITHUB_REF`, `GITHUB_SHA` env vars for provenance
- [x] 1.4 Add unit test for CI flag behavior (forced SARIF, summary output)

## 2. SARIF version control provenance

- [x] 2.1 Update `writeSARIF()` in `internal/report/sarif.go` to accept a `CIInfo` struct
- [x] 2.2 Add `versionControlProvenance` to each `run` object when CI info is available
- [x] 2.3 Fields: `repositoryUri` from `GITHUB_REPOSITORY`, `branch` from `GITHUB_REF`, `revisionId` from `GITHUB_SHA`
- [x] 2.4 Omit provenance when env vars absent
- [x] 2.5 Add unit test: SARIF with and without provenance

## 3. CI summary line

- [x] 3.1 Add `writeCISummary(results []Result, w io.Writer)` to `internal/report/format.go`
- [x] 3.2 Output one-line JSON: `{"critical":N,"high":N,"medium":N,"low":N,"info":N,"pass":N,"servers":N}`
- [x] 3.3 Called instead of main report output when `--ci` is set
- [x] 3.4 Add unit test for summary JSON shape

## 4. GitHub Action definition

- [x] 4.1 Create `action/action.yml` -- composite action with inputs, outputs, and steps
- [x] 4.2 Inputs: `format`, `severity-min`, `trust-config`, `targets`, `probe-depth`, `no-cve-scan`
- [x] 4.3 Outputs: `critical-count`, `high-count`, `medium-count`, `low-count`, `sarif-file`
- [x] 4.4 Step 1: download mcp-audit binary from GitHub Releases (or `go install`)
- [x] 4.5 Step 2: run `mcp-audit scan --ci` with configured inputs
- [x] 4.6 Step 3: upload SARIF using `github/codeql-action/upload-sarif@v3` when findings exist
- [x] 4.7 Step 4: parse summary for output values, exit with failure on findings above threshold

## 5. Pre-commit hook definition

- [x] 5.1 Create `.pre-commit-hooks.yaml` in repo root
- [x] 5.2 Define hook `id: mcp-audit`, `name: MCP Audit`, `entry: mcp-audit static --no-color`
- [x] 5.3 Set `language: system`, `pass_filenames: false`, `always_run: false`
- [x] 5.4 Set `files` filter to `\.mcp\.json$|mcp.*\.json$|config\.toml$` (MCP config file patterns)
- [x] 5.5 Add hook documentation in README.md

## 6. Self-test workflow

- [x] 6.1 Create `.github/workflows/audit-self-test.yml`
- [x] 6.2 Workflow triggers on push/PR to main
- [x] 6.3 Uses the local action via `uses: ./action` (relative path)
- [x] 6.4 Verifies action works against mcp-audit's own repository

## 7. Validation

- [x] 7.1 Run `just check` -- zero lint issues
- [x] 7.2 Run `go test ./...` -- all tests pass including CI mode tests
- [x] 7.3 Test action locally with `act` or push to verify workflow
- [x] 7.4 Test pre-commit hook: install in sample repo, stage `.mcp.json`, verify hook runs
