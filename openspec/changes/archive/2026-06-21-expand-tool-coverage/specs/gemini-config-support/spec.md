# gemini-config-support Specification

## Purpose
Discover and parse Gemini CLI and Antigravity MCP configurations from standard MCP config paths.

## Requirements

### Requirement: Discover Gemini CLI MCP config
The system SHALL discover MCP server configurations from `.mcp.json` (project) and `~/.gemini/settings.json` (global) for Gemini CLI and Antigravity.

#### Scenario: Gemini project config
- **WHEN** `.mcp.json` exists in the working directory
- **THEN** the scanner extracts MCP server entries with `Tool: "gemini"`

#### Scenario: Gemini global config
- **WHEN** `~/.gemini/settings.json` exists with `mcpServers` key
- **THEN** the scanner extracts all MCP server entries

#### Scenario: Gemini not installed
- **WHEN** neither `.mcp.json` nor `~/.gemini/settings.json` exist
- **THEN** the scanner reports "gemini: not found" and continues

### Requirement: Parse Gemini settings format
The system SHALL parse Gemini's `settings.json` using the existing `parseMcpServers` parser. If `mcpServers` key is not at the top level but nested under an `mcp` key, the parser SHALL check both locations.

#### Scenario: Nested mcpServers
- **WHEN** `settings.json` has `{"mcp": {"mcpServers": {...}}}`
- **THEN** the parser extracts servers from the nested path
