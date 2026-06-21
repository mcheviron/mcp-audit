# extensible-tool-registry Specification

## Purpose
Load tool parser definitions from an external JSON file, merge with built-in defaults, and validate at startup. Export `ToolParser` and `RegisterTool` for programmatic extension.

## Requirements

### Requirement: Load user-defined tools from config file
The system SHALL load additional tool parser definitions from `~/.config/mcp-audit/tools.json` at startup and merge them with built-in parsers. User-defined tools with the same `name` as a built-in tool SHALL override the built-in definition entirely.

#### Scenario: User adds a new tool
- **WHEN** `tools.json` defines a tool `"my-tool"` with format `"json"`, server key `"mcpServers"`, and platform paths
- **THEN** the tool is available during config discovery alongside built-in tools

#### Scenario: User overrides a built-in tool
- **WHEN** `tools.json` defines a tool named `"cursor"` with custom paths
- **THEN** the user's cursor definition replaces the built-in definition

#### Scenario: Malformed tools.json
- **WHEN** `tools.json` contains invalid JSON
- **THEN** the system logs a warning and continues with built-in tools only

#### Scenario: Missing tools.json
- **WHEN** `tools.json` does not exist at the default or specified path
- **THEN** the system uses built-in tools only, with no error

#### Scenario: Custom tools config path
- **WHEN** user specifies `--tools-config /path/to/custom-tools.json`
- **THEN** the system loads tools from that path instead of the default

### Requirement: ToolParser struct is exported
The `ToolParser` struct and `RegisterTool` function SHALL be exported from the `config` package so external Go packages can register tools programmatically.

#### Scenario: Programmatic registration
- **WHEN** a Go package imports `internal/config` and calls `config.RegisterTool(config.ToolParser{...})`
- **THEN** the tool is added to the registry and available for discovery

### Requirement: Format-based parser dispatch
The `ToolParser` struct SHALL include a `Format` field (`"json"` or `"toml"`). When `Format` is `"json"`, the system SHALL dispatch to the existing `parseMcpServers` parser. When `Format` is `"toml"`, the system SHALL dispatch to `parseCodexToml`. Tools registered without an explicit `Parse` function SHALL have one selected based on `Format`.

#### Scenario: JSON format dispatch
- **WHEN** a tool is registered with `Format: "json"` and no `Parse` function
- **THEN** `parseMcpServers` is assigned as the parser

#### Scenario: TOML format dispatch
- **WHEN** a tool is registered with `Format: "toml"` and no `Parse` function
- **THEN** `parseCodexToml` is assigned as the parser

#### Scenario: Explicit Parse function takes precedence
- **WHEN** a tool is registered with `Format: "json"` and an explicit `Parse: parseContinue`
- **THEN** the explicit `Parse` function is used, overriding the format-based default

### Requirement: Tools merge deduplication
The system SHALL deduplicate tool definitions by name when merging user and built-in registries. The user definition wins on conflict. A warning SHALL be logged when a user tool overrides a built-in tool.

#### Scenario: User tool overrides built-in with warning
- **WHEN** `tools.json` defines a tool `"cursor"` that overrides the built-in cursor entry
- **THEN** a warning is logged: `"user tool 'cursor' overrides built-in tool"`
