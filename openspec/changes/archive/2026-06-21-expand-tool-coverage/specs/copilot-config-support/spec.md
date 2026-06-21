# copilot-config-support Specification

## Purpose
Discover and parse GitHub Copilot CLI MCP configurations from platform-specific config file paths.

## Requirements

### Requirement: Discover GitHub Copilot CLI MCP config
The system SHALL discover MCP server configurations from GitHub Copilot CLI's config file at `~/.copilot/mcp-config.json` (all platforms).

#### Scenario: Copilot CLI config file exists
- **WHEN** `~/.copilot/mcp-config.json` exists and contains valid `mcpServers` entries
- **THEN** the scanner extracts all MCP server entries with `Tool: "copilot-cli"`

#### Scenario: Copilot CLI not installed
- **WHEN** `~/.copilot/mcp-config.json` does not exist
- **THEN** the scanner reports "copilot-cli: not found" and continues

### Requirement: Parse Copilot mcpServers format
The system SHALL parse Copilot's `mcpServers` JSON using the existing `parseMcpServers` parser. Copilot uses the same `mcpServers` key and structure as Claude Desktop, Cursor, and VS Code.

#### Scenario: Stdio and HTTP servers mixed
- **WHEN** Copilot config contains both command-based and url-based server entries
- **THEN** both are extracted with correct transport types
