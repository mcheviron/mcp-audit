# static-config-scanning Delta Spec

## MODIFIED Requirements

### Requirement: Discover MCP configs across AI tools
The system SHALL locate MCP server configurations in the user's local environment by searching known config paths for 12 AI coding tools: Claude Desktop, Claude Code CLI, Cursor, Windsurf, VS Code, GitHub Copilot CLI, Codex CLI, Gemini CLI, Continue, OpenCode, Cline/Roo Code, and Zed.

#### Scenario: All tools configured
- **WHEN** user has MCP servers configured in Claude Desktop, Cursor, VS Code, Copilot CLI, and Claude Code CLI
- **THEN** the scanner discovers all 5 config files and extracts 100% of declared MCP server entries

#### Scenario: No configs found
- **WHEN** none of the 12 AI tools have MCP configurations
- **THEN** the scanner reports zero MCP servers found and exits with status 0

#### Scenario: Partial config — one tool missing
- **WHEN** user has MCP configs in Cursor but not in Claude Desktop (config file absent or empty)
- **THEN** the scanner skips the missing config without error and continues scanning remaining tools

#### Scenario: Codex TOML config discovered
- **WHEN** user has `~/.codex/config.toml` with valid `[mcp_servers]` sections
- **THEN** the scanner discovers Codex MCP servers using the TOML parser

#### Scenario: Gemini nested config discovered
- **WHEN** `~/.gemini/settings.json` nests `mcpServers` under an `mcp` key
- **THEN** the scanner discovers servers from the nested path

#### Scenario: Zed underscore key variant
- **WHEN** `~/.config/zed/settings.json` uses `"mcp_servers"` (underscore) key
- **THEN** the scanner discovers servers using the normalized key detection
