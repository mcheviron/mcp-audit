## Why

mcp-audit currently discovers MCP configurations from 6 AI tools (Claude Desktop, Cursor, Windsurf, VS Code, Continue, OpenCode). Research shows these tools collectively cover less than 20% of the AI coding tool market. The four missing dominant tools — GitHub Copilot (75% any-use), Claude Code CLI (54% any-use), Codex CLI (21-31% any-use), and Gemini CLI (37% any-use) — represent over 80% of developer AI tool usage. Without their config paths, mcp-audit misses the vast majority of MCP servers deployed in the wild, making it ineffective as a production security auditor.

## What Changes

- Add built-in parser for **GitHub Copilot CLI**: JSON format at `~/.copilot/mcp-config.json`
- Add built-in parser for **Claude Code CLI**: JSON format at `.mcp.json` (project) and `~/.claude/mcp.json` (global)
- Add built-in parser for **Codex CLI**: TOML format at `~/.codex/config.toml` and `.codex/config.toml` (requires `pluggable-tool-registry` for TOML parsing)
- Add built-in parser for **Gemini CLI / Antigravity**: JSON format at `.mcp.json` and `~/.gemini/settings.json`
- Add built-in parser for **Cline / Roo Code** (VS Code extension ecosystem): JSON at VS Code extension storage paths
- Add built-in parser for **Zed**: JSON format with non-standard top-level key at `~/.config/zed/settings.json`
- Each tool gets a `ToolParser` entry in the built-in registry with platform-specific config paths

## Capabilities

### New Capabilities

- `copilot-config-support`: Discover and parse GitHub Copilot CLI MCP configurations
- `claude-code-cli-config-support`: Discover and parse Claude Code CLI MCP configurations from project and global paths
- `gemini-config-support`: Discover and parse Gemini CLI and Antigravity MCP configurations
- `cline-roo-config-support`: Discover and parse Cline and Roo Code VS Code extension MCP configurations
- `zed-config-support`: Discover and parse Zed editor MCP configurations

### Modified Capabilities

- `static-config-scanning`: Requirement updated from "5 AI coding tools" to "12 AI coding tools" in the SHALL clause. Opencode added to the existing spec text (was missing despite being implemented).

## Non-goals

- Project-scoped discovery for these tools (handled by `project-scoped-discovery`)
- TOML parsing implementation (handled by `pluggable-tool-registry`)
- Cloud Desktop, Hermes, Pi, or other not-yet-launched tools
- Continue and OpenCode removal (kept for completeness)

## Impact

- `internal/config/discover.go`: 6 new `ToolParser` entries in the registry
- `internal/config/parser.go`: New parser functions for Gemini settings format and Zed format
- `internal/config/claude_paths.go`: Extend `claudePaths` to include Claude Code CLI paths
- `.github/workflows/`: No impact
- `go.mod`: No new dependencies (TOML handled by `pluggable-tool-registry`)
