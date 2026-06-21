# zed-config-support Specification

## Purpose
Discover and parse Zed editor MCP configurations from platform-specific config paths.

## Requirements

### Requirement: Discover Zed MCP config
The system SHALL discover MCP server configurations from Zed's settings file at `~/.config/zed/settings.json` (macOS and Linux).

#### Scenario: Zed config with mcp_servers
- **WHEN** `~/.config/zed/settings.json` exists with `"mcp_servers"` key (underscore variant)
- **THEN** the scanner extracts all MCP server entries with `Tool: "zed"`

#### Scenario: Zed config with mcpServers
- **WHEN** `~/.config/zed/settings.json` exists with `"mcpServers"` key (camelCase variant)
- **THEN** the scanner extracts all MCP server entries

#### Scenario: Zed not installed
- **WHEN** `~/.config/zed/settings.json` does not exist
- **THEN** the scanner reports "zed: not found" and continues

### Requirement: Normalize Zed server key variant
The system SHALL detect which top-level key Zed uses for MCP configs (`"mcp_servers"` or `"mcpServers"`) and parse accordingly. Both variants SHALL produce identical `ServerEntry` results.

#### Scenario: Underscore variant parsed correctly
- **WHEN** settings.json uses `"mcp_servers"` key
- **THEN** server entries are extracted identically to the `"mcpServers"` case
