# static-config-scanning Specification

## Purpose
Discover and parse MCP server configurations across AI coding tools from platform-specific config file paths.
## Requirements
### Requirement: Discover MCP configs across AI tools
The system SHALL locate MCP server configurations by searching both project-scoped config paths (walking upward from the working directory or `--project-dir`) and global config paths (home directory), for 12 AI coding tools: Claude Desktop, Claude Code CLI, Cursor, Windsurf, VS Code, GitHub Copilot CLI, Codex CLI, Gemini CLI, Continue, OpenCode, Cline/Roo Code, and Zed. The system SHALL also discover configurations from any additional tools registered via the extensible tool registry (`~/.config/mcp-audit/tools.json` or programmatic registration). Project configs SHALL take precedence over global configs for the same server name within the same tool. When `--no-project-config` is set, only global configs SHALL be searched.

#### Scenario: All tools configured
- **WHEN** user has MCP servers configured in Claude Desktop, Cursor, VS Code, Copilot CLI, and Claude Code CLI
- **THEN** the scanner discovers all 5 config files and extracts 100% of declared MCP server entries

#### Scenario: User-defined tool discovered
- **WHEN** a user has registered a new tool via `tools.json` and that tool's config file exists
- **THEN** the scanner discovers the user-defined tool's MCP servers alongside built-in tools

#### Scenario: Project + global discovery
- **WHEN** user has `.mcp.json` in their project and `claude_desktop_config.json` in their home directory
- **THEN** the scanner discovers servers from both, with project servers taking precedence for name conflicts

#### Scenario: Global only with flag
- **WHEN** `--no-project-config` is specified
- **THEN** only global config files are discovered (current behavior)

#### Scenario: No configs found
- **WHEN** none of the 12 AI tools have MCP configurations
- **THEN** the scanner reports zero MCP servers found and exits with status 0

#### Scenario: Partial config — one tool missing
- **WHEN** user has MCP configs in Cursor but not in Claude Desktop (config file absent or empty)
- **THEN** the scanner skips the missing config without error and continues scanning remaining tools

#### Scenario: TOML-format tool discovered
- **WHEN** a tool is registered with `Format: "toml"` and a TOML config file exists at its path
- **THEN** the scanner uses the TOML parser to extract server entries with the same `ServerEntry` structure as JSON tools

#### Scenario: Codex TOML config discovered
- **WHEN** user has `~/.codex/config.toml` with valid `[mcp_servers]` sections
- **THEN** the scanner discovers Codex MCP servers using the TOML parser

#### Scenario: Gemini nested config discovered
- **WHEN** `~/.gemini/settings.json` nests `mcpServers` under an `mcp` key
- **THEN** the scanner discovers servers from the nested path

#### Scenario: Zed underscore key variant
- **WHEN** `~/.config/zed/settings.json` uses `"mcp_servers"` (underscore) key
- **THEN** the scanner discovers servers using the normalized key detection

### Requirement: Parse MCP server metadata from config files
The system SHALL extract for each discovered MCP server: the server name, transport type (stdio or HTTP), endpoint URL or command, package identifier if present, and `env` and `headers` blocks. `env` and `headers` fields SHALL be preserved on the server entry for credential scanning and transport auth configuration. `env` and `headers` values of non-string JSON types (number, bool) SHALL be coerced to strings so they can be scanned and passed to transports.

#### Scenario: Stdio transport
- **WHEN** a config entry specifies `"command": "npx"` with `"args": ["-y", "@scope/mcp-server"]`
- **THEN** the parser extracts transport=stdio, command=npx, package=@scope/mcp-server

#### Scenario: HTTP transport
- **WHEN** a config entry specifies `"url": "http://localhost:3000/mcp"`
- **THEN** the parser extracts transport=http, endpoint=http://localhost:3000/mcp

#### Scenario: Malformed config
- **WHEN** a config entry is missing both `command` and `url` fields
- **THEN** the parser logs a warning with the server name and skips that entry

#### Scenario: Env block extracted
- **WHEN** a config file contains `"mcpServers": {"myserver": {"command": "npx", "args": ["-y", "pkg"], "env": {"NODE_ENV": "production"}}}`
- **THEN** the server entry's `Env` contains `{"NODE_ENV": "production"}`

#### Scenario: Headers extracted
- **WHEN** a config file contains `"mcpServers": {"myserver": {"url": "https://example.com", "headers": {"x-api-key": "test"}}}`
- **THEN** the server entry's `Headers` contains `{"x-api-key": "test"}`

#### Scenario: Legacy config without env/headers
- **WHEN** a config file does not contain `env` or `headers` fields
- **THEN** the server entry's `Env` and `Headers` are nil

### Requirement: Cross-platform config path resolution
The system SHALL resolve config file paths appropriate to the host OS, including platform-specific default locations, XDG/user-home conventions, and project-relative paths.

#### Scenario: macOS paths
- **WHEN** running on macOS
- **THEN** Claude Desktop config is resolved at `~/Library/Application Support/Claude/claude_desktop_config.json`, project configs use cwd-anchored relative paths

#### Scenario: Linux paths
- **WHEN** running on Linux
- **THEN** config paths use XDG conventions where applicable (e.g., `~/.config/`), project configs use cwd-anchored relative paths

#### Scenario: Windows paths
- **WHEN** running on Windows
- **THEN** global config paths use `%APPDATA%`, project configs use cwd-anchored relative paths

### Requirement: File-not-found is non-fatal
The system SHALL treat missing config files as normal (not an error) and report them as "not found" rather than failing the scan.

#### Scenario: Tool not installed
- **WHEN** Windsurf is not installed and its config path does not exist
- **THEN** scanner reports "Windsurf: not found" and continues to next tool

### Requirement: Merge user and built-in tool registries
The system SHALL merge user-defined tools from `~/.config/mcp-audit/tools.json` (or the path specified by `--tools-config`) with the built-in tool registry before config discovery. User tools with the same `name` SHALL override built-in tools. The merge SHALL happen at startup, before `Discover()` is called.

#### Scenario: User tools merge before discovery
- **WHEN** the scanner starts with a valid `tools.json`
- **THEN** `Discover()` sees the merged registry containing both built-in and user-defined tools
