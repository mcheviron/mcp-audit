## Context

mcp-audit is a CLI tool with no automated CI/CD story. MCPShield ships a GitHub Action and pre-commit hook. Enterprise adoption of security tools depends on pipeline integration — if it can't run in CI, it's not part of the security posture. The GitHub Actions marketplace is the primary distribution channel for CI security tools in the GitHub ecosystem.

Pre-commit hooks provide the fastest feedback loop — catching issues before they reach a commit. The pre-commit framework is the de facto standard for polyglot pre-commit hooks, with a simple YAML registry format.

## Goals / Non-Goals

**Goals:**
- Composite GitHub Action that installs and runs mcp-audit
- Action inputs: format, severity-min, trust-config, targets, probe-depth, no-cve-scan
- Action outputs: critical-count, high-count, medium-count, sarif-file
- SARIF upload to GitHub Code Scanning when findings exist
- Pre-commit hook definition for the pre-commit framework (static scan only)
- New `--ci` CLI flag for CI-optimized output

**Non-Goals:**
- GitLab CI, CircleCI, or other CI platforms
- Automated PR comments
- Notifications (Slack, email, webhook)
- GitHub App or bot
- Dynamic probing in pre-commit (too slow)

## Decisions

**Decision: Composite action over Docker action**
- Rationale: Composite actions are simpler, faster (no Docker pull), and work on all GitHub-hosted runners. mcp-audit is a single static binary — download and run. Docker action would add complexity for no benefit.
- The action downloads the mcp-audit binary from GitHub Releases using the `github-script` action or a direct curl. For pinned versions, users reference `uses: mcp-audit/action@v1`.

**Decision: Pre-commit hook runs `mcp-audit static` only**
- Rationale: Pre-commit hooks must be fast (<2 seconds). Dynamic probing can take 30+ seconds and requires network access. Static analysis (typosquat + CVE) runs in milliseconds and catches the most critical issues before commit.
- Users who need pre-commit probing can configure a separate manual stage hook.

**Decision: `--ci` flag triggers SARIF + machine-readable summary**
- Rationale: CI environments need structured output for gate decisions. The `--ci` flag:
  1. Forces SARIF output (regardless of `--format`)
  2. Writes a one-line JSON summary to stdout: `{"critical": N, "high": N, "medium": N, "low": N, "info": N, "pass": N, "servers": N}`
  3. Enriches SARIF with `versionControlProvenance` (repo URI, branch, commit SHA from `GITHUB_*` env vars)
  4. Exit code 0 = clean, 1 = findings at or above `--severity-min`, 2 = scan error

**Decision: SARIF upload via `github/codeql-action/upload-sarif`**
- Rationale: GitHub Code Scanning natively supports SARIF ingestion. Rather than building a custom upload, the action pipes SARIF output to the official upload action. This gives users Code Scanning alerts, PR annotations, and the security tab UI for free.

## Risks / Trade-offs

- **Action depends on GitHub Releases for binary download** → Mitigation: Users can pin to a specific version tag. The action fails gracefully with a clear error if the binary can't be downloaded.
- **Pre-commit hook requires mcp-audit installed** → Mitigation: The hook definition includes `additional_dependencies` and setup instructions. Users install mcp-audit once via `brew`, `go install`, or direct download.
