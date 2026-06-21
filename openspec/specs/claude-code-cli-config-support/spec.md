# claude-code-cli-config-support Specification

## Purpose
Discover and parse Claude Code CLI MCP configurations from project and global config file paths.

## Requirements

### Requirement: Discover Claude Code CLI project config
The system SHALL discover MCP server configurations from `.mcp.json` in the project root (current working directory or `--project-dir`).

#### Scenario: Project .mcp.json exists
- **WHEN** `.mcp.json` exists in the working directory with valid `mcpServers`
- **THEN** the scanner extracts all MCP server entries with `Tool: "claude-code"`

### Requirement: Discover Claude Code CLI global config
The system SHALL discover MCP server configurations from `~/.claude/mcp.json` (all platforms) when no project config exists or in addition to the project config.

#### Scenario: Global config fallback
- **WHEN** no `.mcp.json` exists in the working directory but `~/.claude/mcp.json` exists
- **THEN** the scanner discovers servers from the global config

#### Scenario: Both project and global configs exist
- **WHEN** both `.mcp.json` and `~/.claude/mcp.json` exist
- **THEN** the scanner merges both, with project servers taking precedence for same-name conflicts
