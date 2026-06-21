## Why

mcp-audit is a CLI tool with no CI/CD integration story. Security tools that can't run in pipelines get skipped. MCPShield ships a GitHub Action, and enterprise security teams expect pre-commit hooks and CI gates. Without these, mcp-audit is a manual-only tool — used once, forgotten, never enforced. Adding a GitHub Action, pre-commit hook, and CI-optimized output modes makes mcp-audit a gate that blocks vulnerable MCP configs from reaching production, not just a scanner someone runs on their laptop.

## What Changes

- **GitHub Action**: Official `mcp-audit-action` in a new `action/` directory (composite action, uses the Go binary)
  - Inputs: `format`, `severity-min`, `trust-config`, `targets`, `probe-depth`, `no-cve-scan`
  - Outputs: `critical-count`, `high-count`, `medium-count`, `sarif-file`
  - Uploads SARIF to GitHub Code Scanning when findings exist
  - Fails the workflow when CRITICAL or HIGH findings are detected (configurable)
- **Pre-commit hook**: `.pre-commit-hooks.yaml` in repo root for pre-commit framework integration
  - Runs `mcp-audit static` on staged config changes
  - Fast path — no network probes, just typosquat + CVE checks
- **CI-optimized exit codes**: New `--ci` flag that produces machine-readable summary on stdout
  - Exit code 0 → clean, exit code 1 → findings at or above severity threshold, exit code 2 → scan error
- **SARIF CI mode**: SARIF output includes `versionControlProvenance` and repository URI when `--ci` is set

## Capabilities

### New Capabilities

- `github-action`: Official GitHub Action that runs mcp-audit in CI, uploads SARIF to Code Scanning, and gates on severity thresholds
- `pre-commit-integration`: Pre-commit hook definition for the pre-commit framework that runs static analysis on staged MCP configs

### Modified Capabilities

- `report-formatting`: SARIF output gains `versionControlProvenance` and repository URI fields when `--ci` flag is set. New `--ci` flag adds machine-readable summary line to stdout.

## Non-goals

- GitLab CI, CircleCI, or other CI platform actions (GitHub Action only for now)
- Automated PR comments with findings
- Slack/email/webhook notifications
- mcp-audit as a GitHub App or bot
- Pre-commit hook for dynamic probing (too slow for pre-commit)

## Impact

- `action/action.yml`: New file, composite GitHub Action definition
- `action/entrypoint.sh`: New file, action entrypoint script
- `.pre-commit-hooks.yaml`: New file, pre-commit hook registry entry
- `cmd/mcp-audit/main.go`: New `--ci` flag on scan/static/probe subcommands
- `internal/report/sarif.go`: CI-aware SARIF output with provenance
- `internal/report/format.go`: CI summary line on stdout
- `README.md`: Installation and usage instructions for Action and pre-commit
- `.github/workflows/`: Self-test workflow that dogfoods the Action on this repo
