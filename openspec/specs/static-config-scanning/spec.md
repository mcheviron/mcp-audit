# static-config-scanning Specification

## Purpose
TBD - created by archiving change build-mcp-auditor. Update Purpose after archive.
## Requirements
### Requirement: Discover MCP configs across AI tools
The system SHALL locate MCP server configurations in the user's local environment by searching known config paths for 5 AI coding tools: Claude Desktop, Cursor, Windsurf, VS Code, and Continue.

#### Scenario: All tools configured
- **WHEN** user has MCP servers configured in Claude Desktop, Cursor, and VS Code
- **THEN** the scanner discovers all 3 config files and extracts 100% of declared MCP server entries

#### Scenario: No configs found
- **WHEN** none of the 5 AI tools have MCP configurations
- **THEN** the scanner reports zero MCP servers found and exits with status 0

#### Scenario: Partial config — one tool missing
- **WHEN** user has MCP configs in Cursor but not in Claude Desktop (config file absent or empty)
- **THEN** the scanner skips the missing config without error and continues scanning remaining tools

### Requirement: Parse MCP server metadata from config files
The system SHALL extract for each discovered MCP server: the server name, transport type (stdio or HTTP), endpoint URL or command, and package identifier if present.

#### Scenario: Stdio transport
- **WHEN** a config entry specifies `"command": "npx"` with `"args": ["-y", "@scope/mcp-server"]`
- **THEN** the parser extracts transport=stdio, command=npx, package=@scope/mcp-server

#### Scenario: HTTP transport
- **WHEN** a config entry specifies `"url": "http://localhost:3000/mcp"`
- **THEN** the parser extracts transport=http, endpoint=http://localhost:3000/mcp

#### Scenario: Malformed config
- **WHEN** a config entry is missing both `command` and `url` fields
- **THEN** the parser logs a warning with the server name and skips that entry

### Requirement: Cross-platform config path resolution
The system SHALL resolve config file paths appropriate to the host OS, including platform-specific default locations and XDG/user-home conventions.

#### Scenario: macOS paths
- **WHEN** running on macOS
- **THEN** Claude Desktop config is resolved at `~/Library/Application Support/Claude/claude_desktop_config.json`

#### Scenario: Linux paths
- **WHEN** running on Linux
- **THEN** config paths use XDG conventions where applicable (e.g., `~/.config/`)

### Requirement: File-not-found is non-fatal
The system SHALL treat missing config files as normal (not an error) and report them as "not found" rather than failing the scan.

#### Scenario: Tool not installed
- **WHEN** Windsurf is not installed and its config path does not exist
- **THEN** scanner reports "Windsurf: not found" and continues to next tool

