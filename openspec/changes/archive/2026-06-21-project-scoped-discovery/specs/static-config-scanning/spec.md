# static-config-scanning Delta Spec

## MODIFIED Requirements

### Requirement: Discover MCP configs across AI tools
The system SHALL locate MCP server configurations by searching both project-scoped config paths (walking upward from the working directory or `--project-dir`) and global config paths (home directory). Project configs SHALL take precedence over global configs for the same server name within the same tool. When `--no-project-config` is set, only global configs SHALL be searched.

#### Scenario: Project + global discovery
- **WHEN** user has `.mcp.json` in their project and `claude_desktop_config.json` in their home directory
- **THEN** the scanner discovers servers from both, with project servers taking precedence for name conflicts

#### Scenario: Global only with flag
- **WHEN** `--no-project-config` is specified
- **THEN** only global config files are discovered (current behavior)

#### Scenario: All tools configured
- **WHEN** user has MCP servers configured in Claude Desktop, Cursor, and VS Code
- **THEN** the scanner discovers all 3 config files and extracts 100% of declared MCP server entries

#### Scenario: No configs found
- **WHEN** none of the AI tools have MCP configurations at either project or global scope
- **THEN** the scanner reports zero MCP servers found and exits with status 0

### Requirement: Cross-platform config path resolution
The system SHALL resolve config file paths appropriate to the host OS, including platform-specific default locations, XDG/user-home conventions, and project-relative paths.

#### Scenario: macOS paths
- **WHEN** running on macOS
- **THEN** global Claude Desktop config is resolved at `~/Library/Application Support/Claude/claude_desktop_config.json`, project configs use cwd-anchored relative paths

#### Scenario: Linux paths
- **WHEN** running on Linux
- **THEN** global config paths use XDG conventions, project configs use cwd-anchored relative paths

#### Scenario: Windows paths
- **WHEN** running on Windows
- **THEN** global config paths use `%APPDATA%`, project configs use cwd-anchored relative paths
