# cline-roo-config-support Specification

## Purpose
Discover and parse Cline and Roo Code VS Code extension MCP configurations.

## Requirements

### Requirement: Discover Cline/Roo Code MCP configs
The system SHALL discover MCP server configurations from Cline and Roo Code's VS Code extension storage paths. On macOS: `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`. On Linux: `~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`.

#### Scenario: Cline config exists
- **WHEN** the Cline MCP settings file exists and contains `mcpServers`
- **THEN** the scanner extracts all MCP server entries with `Tool: "cline-roo"`

#### Scenario: Cline not installed
- **WHEN** the Cline settings path does not exist
- **THEN** the scanner reports "cline-roo: not found" and continues

### Requirement: Parse Cline mcpServers format
The system SHALL parse Cline's `mcpServers` JSON using the existing `parseMcpServers` parser. Cline uses the standard `mcpServers` key at the top level of settings JSON.

#### Scenario: Multiple servers
- **WHEN** Cline settings define 3 MCP servers
- **THEN** all 3 are extracted with correct transport types
