# static-config-scanning Delta Spec

## MODIFIED Requirements

### Requirement: Discover MCP configs across AI tools
The system SHALL locate MCP server configurations in the user's local environment by searching known config paths for a built-in set of AI coding tools, including Claude Desktop, Cursor, Windsurf, VS Code, Continue, and OpenCode. The system SHALL also discover configurations from any additional tools registered via the extensible tool registry (`~/.config/mcp-audit/tools.json` or programmatic registration).

#### Scenario: All built-in tools configured
- **WHEN** user has MCP servers configured in Claude Desktop, Cursor, and VS Code
- **THEN** the scanner discovers all 3 config files and extracts 100% of declared MCP server entries

#### Scenario: User-defined tool discovered
- **WHEN** a user has registered a new tool via `tools.json` and that tool's config file exists
- **THEN** the scanner discovers the user-defined tool's MCP servers alongside built-in tools

#### Scenario: No configs found
- **WHEN** none of the registered tools have MCP configurations
- **THEN** the scanner reports zero MCP servers found and exits with status 0

#### Scenario: Partial config — one tool missing
- **WHEN** user has MCP configs in Cursor but not in Claude Desktop (config file absent or empty)
- **THEN** the scanner skips the missing config without error and continues scanning remaining tools

#### Scenario: TOML-format tool discovered
- **WHEN** a tool is registered with `Format: "toml"` and a TOML config file exists at its path
- **THEN** the scanner uses the TOML parser to extract server entries with the same `ServerEntry` structure as JSON tools

## ADDED Requirements

### Requirement: Merge user and built-in tool registries
The system SHALL merge user-defined tools from `~/.config/mcp-audit/tools.json` (or the path specified by `--tools-config`) with the built-in tool registry before config discovery. User tools with the same `name` SHALL override built-in tools. The merge SHALL happen at startup, before `Discover()` is called.

#### Scenario: User tools merge before discovery
- **WHEN** the scanner starts with a valid `tools.json`
- **THEN** `Discover()` sees the merged registry containing both built-in and user-defined tools
