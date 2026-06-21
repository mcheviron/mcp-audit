# pre-commit-integration Specification

## Purpose
Pre-commit hook definition for the pre-commit framework that runs mcp-audit static analysis on staged files.

## Requirements

### Requirement: Pre-commit hook definition
The system SHALL provide a `.pre-commit-hooks.yaml` file in the repository root defining a hook with id `mcp-audit` that runs `mcp-audit static --no-color` on staged MCP config files.

#### Scenario: Hook registration
- **WHEN** a user adds `- repo: https://github.com/mcp-audit/mcp-audit` with hook `mcp-audit` to their `.pre-commit-config.yaml`
- **THEN** the pre-commit framework runs `mcp-audit static` on every commit

### Requirement: Static-only scan
The hook SHALL run only static analysis (typosquat, credentials, CVE checks). Dynamic probing SHALL NOT be performed during pre-commit due to time constraints.

#### Scenario: Fast pre-commit check
- **WHEN** the hook runs on a commit
- **THEN** the scan completes in under 2 seconds with no network requests beyond CVE cache

### Requirement: Hook passes staged config files
The hook SHALL scan staged MCP config files. If no MCP config files are staged, the hook SHALL pass (no-op).

#### Scenario: No MCP configs staged
- **WHEN** a commit contains only Go source files
- **THEN** the hook exits 0 without running a scan

#### Scenario: Staged .mcp.json
- **WHEN** a commit includes changes to `.mcp.json`
- **THEN** the hook runs static analysis on that file

### Requirement: Hook fails on findings
The hook SHALL exit with code 1 when CRITICAL or HIGH findings are detected, blocking the commit. MEDIUM, LOW, INFO, and PASS findings SHALL allow the commit to proceed.

#### Scenario: CRITICAL finding blocks commit
- **WHEN** static scan finds a typosquat match against a blocked package
- **THEN** the commit is blocked with the finding details printed

#### Scenario: INFO finding allows commit
- **WHEN** static scan finds a potential typosquat (Levenshtein <= 2 from trusted)
- **THEN** the commit proceeds but the finding is displayed as a warning
