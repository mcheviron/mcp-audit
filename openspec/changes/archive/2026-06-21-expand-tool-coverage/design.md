## Context

mcp-audit supports 6 AI tools. The 4 market-dominant tools missing are GitHub Copilot, Claude Code CLI, Codex CLI, and Gemini CLI. Claude Code CLI in particular is already supported via Claude Desktop paths but the CLI stores config at different paths (`.mcp.json` project-level, `~/.claude/mcp.json` global). Codex is the only TOML client and requires the `pluggable-tool-registry` change as a prerequisite.

Each tool uses JSON format except Codex (TOML). The `mcpServers` JSON structure is shared by Copilot, Claude Code CLI, and Gemini. Cline/Roo Code use VS Code extension storage paths with the same JSON shape as VS Code. Zed uses a unique top-level key (`"mcp_servers"` instead of `"mcpServers"`).

The `expand-tool-coverage` change depends on `pluggable-tool-registry` only for Codex TOML support. The other 5 tools (Copilot, Claude Code CLI, Gemini, Cline/Roo, Zed) can be added independently as JSON-format parsers.

## Goals / Non-Goals

**Goals:**
- Add 6 new `ToolParser` entries to the built-in registry covering Copilot, Claude Code CLI, Codex CLI, Gemini CLI, Cline/Roo Code, and Zed
- Each entry defines platform-specific config paths and the appropriate parser function
- All new tools parse into the existing `ServerEntry` struct — no schema changes

**Non-Goals:**
- Cloud Desktop, Hermes, Pi, or unreleased tools
- Project-scoped discovery (separate change)
- Removing Continue or OpenCode (kept for completeness)

## Decisions

**Decision: Claude Code CLI is a separate ToolParser entry from Claude Desktop**
- Rationale: Claude Desktop stores config at `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS). Claude Code CLI stores at `.mcp.json` (project) and `~/.claude/mcp.json` (global). Different paths, different tool name. The `claudePaths` function in `discover.go` returns only the Desktop path. Adding a separate entry avoids modifying the Desktop parser's path logic.
- The parser function is the same: `parseMcpServers`. Only paths differ.

**Decision: Zed uses parseMcpServers with a server key alias**
- Rationale: Zed's config uses `"mcp_servers"` (underscore) instead of `"mcpServers"` (camelCase). Rather than a new parser, we detect the key variant from the parsed JSON and normalize.

**Decision: Copilot has two config roots — Copilot CLI and VS Code Copilot extension**
- Rationale: GitHub Copilot CLI stores at `~/.copilot/mcp-config.json`. VS Code Copilot extension shares `.vscode/mcp.json` with VS Code. The VS Code parser already covers the extension path. Only the Copilot CLI path needs a new entry.

**Decision: Cline and Roo Code share one ToolParser**
- Rationale: Roo Code is a fork of Cline. Both store MCP configs at the same VS Code extension storage paths. One entry covers both with a shared name label `"cline-roo"`.

## Risks / Trade-offs

- **Codex TOML support blocked** → Mitigation: The Codex entry is added to the built-in registry with `Format: "toml"` but discovery skips it (with a debug log) if the TOML parser is not registered. Once `pluggable-tool-registry` ships, Codex discovery activates automatically.
- **Gemini config format may change** → Mitigation: Gemini/Antigravity is a Google product in active development. Config paths are based on current documentation. If paths change, users can override via `tools.json` from `pluggable-tool-registry`.
