## Why

mcp-audit's `Discover()` function only searches user home directory paths (`~/Library/...`, `~/.config/...`, `%APPDATA%/...`). It completely ignores project-scoped MCP configurations. Every major AI tool supports project-level MCP config overrides: `.mcp.json` (Claude Code, Antigravity), `.cursor/mcp.json` (Cursor), `.vscode/mcp.json` (VS Code/Copilot), `.codex/config.toml` (Codex), `.kiro/settings/mcp.json` (Kiro). Enterprise environments increasingly rely on project-scoped configs for policy enforcement. Missing these means mcp-audit produces incomplete audit results — a false sense of security.

## What Changes

- `Discover()` accepts an optional working directory and walks upward to the filesystem root (like git) finding project-scoped config files
- Project configs are merged with global configs — project entries take precedence for the same server name
- New `--project-dir` CLI flag to explicitly specify the project root for discovery
- New `--no-project-config` flag to disable project-scoped discovery (useful for CI where cwd may be irrelevant)
- Each tool's `Paths` function returns both global and project paths; the registry distinguishes them
- Duplicate server entries (same name, same tool) are deduplicated with project-scoped taking priority

## Capabilities

### New Capabilities

- `project-scoped-config-discovery`: Walk the filesystem upward from a starting directory to discover project-level MCP configurations, merging them with global configurations with well-defined precedence rules

### Modified Capabilities

- `static-config-scanning`: `Discover()` signature changes to accept optional working directory. Config entries gain a `Scope` field (`"global"` | `"project"`). Server deduplication by name+tool with project-precedence rule.

## Non-goals

- Recursive directory scanning or workspace monorepo detection
- `.gitignore`-aware config skipping
- Auto-detection of the correct project root (must be explicit or cwd)
- Network-mounted project configs or remote config fetching

## Impact

- `internal/config/discover.go`: `Discover()` signature change to `Discover(cwd string)`, upward walk logic
- `internal/config/types.go`: `Scope` field on `ServerEntry` and `Config`
- `internal/config/parser.go`: No changes
- `cmd/mcp-audit/main.go`: New `--project-dir` and `--no-project-config` flags
- `internal/daemon/watcher.go`: Watch project paths in addition to global paths
- `internal/scanner/scanner.go`: Pass working directory through to `Discover()`
- `internal/proxy/`: No impact
