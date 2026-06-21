# project-scoped-config-discovery Specification

## Purpose
Walk the filesystem upward from a starting directory to discover project-level MCP configurations, merging them with global configurations with well-defined precedence rules.

## Requirements

### Requirement: Walk directory tree for project configs
The system SHALL walk from the specified working directory upward to the filesystem root, checking each ancestor directory for project-scoped MCP config files. The walk SHALL stop at the first directory containing a config file for each tool.

#### Scenario: Config found one level up
- **WHEN** cwd is `/project/src/lib` and `.mcp.json` exists at `/project/.mcp.json`
- **THEN** the scanner discovers the config at `/project/.mcp.json`

#### Scenario: Config at cwd
- **WHEN** `.mcp.json` exists in the current working directory
- **THEN** the scanner discovers the config without walking upward

#### Scenario: No project config anywhere
- **WHEN** no project-scoped config file exists from cwd to filesystem root
- **THEN** the scanner reports no project configs and falls back to global only

#### Scenario: Stop at filesystem root
- **WHEN** the walk reaches the filesystem root without finding a config
- **THEN** the scanner stops walking and does not recurse into system directories

### Requirement: Merge project and global configs by server name
The system SHALL merge project-scoped and global configs for each tool. When the same server name exists in both project and global configs of the same tool, the project definition SHALL take precedence. Servers with different names SHALL be included from both sources.

#### Scenario: Project overrides global server
- **WHEN** a project `.mcp.json` defines server `"db"` with url `http://prod-db/mcp` and global `~/.claude/mcp.json` also defines `"db"` with url `http://staging-db/mcp`
- **THEN** the scanner uses the project definition (url=`http://prod-db/mcp`)

#### Scenario: Non-conflicting servers merged
- **WHEN** project config defines server `"db"` and global config defines server `"slack"`
- **THEN** both servers are included in results

#### Scenario: Same server name across different tools
- **WHEN** Claude Code CLI and Cursor both define a server named `"db"` (different tool entries)
- **THEN** both are included as separate entries (tool identity is part of the dedup key)

### Requirement: ServerEntry Scope field
The system SHALL annotate each `ServerEntry` with a `Scope` field indicating its origin: `"global"` for home-directory configs, `"project"` for working-directory-discovered configs.

#### Scenario: Global scope annotated
- **WHEN** a server entry is discovered from `~/Library/Application Support/Claude/claude_desktop_config.json`
- **THEN** `ServerEntry.Scope` is `"global"`

#### Scenario: Project scope annotated
- **WHEN** a server entry is discovered from `/project/.mcp.json`
- **THEN** `ServerEntry.Scope` is `"project"`

### Requirement: Config Scope field
The system SHALL annotate each `Config` with a `Scope` field indicating the highest-priority scope among its servers. If all servers are global, `Config.Scope` is `"global"`. If any server is from project scope, `Config.Scope` is `"project"`.

#### Scenario: Mixed scope config
- **WHEN** a Config contains both global and project-origin servers
- **THEN** `Config.Scope` is `"project"`

### Requirement: CLI flag for project directory
The system SHALL accept a `--project-dir` CLI flag to specify the starting directory for project-scoped discovery. When omitted, the current working directory SHALL be used.

#### Scenario: Explicit project directory
- **WHEN** `--project-dir /path/to/project` is specified
- **THEN** the scanner walks from `/path/to/project` instead of cwd

### Requirement: Disable project-scoped discovery
The system SHALL accept a `--no-project-config` CLI flag to disable project-scoped discovery entirely. When set, `Discover("")` is called with an empty string, preserving the existing global-only behavior.

#### Scenario: No project config flag set
- **WHEN** `--no-project-config` is specified
- **THEN** only global configs are discovered regardless of cwd
