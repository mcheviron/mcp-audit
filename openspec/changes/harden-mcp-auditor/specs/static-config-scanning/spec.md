## ADDED Requirements

### Requirement: Registry-based tool config discovery
The system SHALL use a registry of `ToolParser` entries — each specifying a tool name, config path resolver, and parse function — instead of hardcoded sequential calls in `Discover()`.

#### Scenario: Adding a new tool
- **WHEN** a developer adds a new AI tool's MCP config format
- **THEN** they register a single `ToolParser` entry and `Discover()` picks it up without editing the core discovery loop

#### Scenario: Deterministic ordering
- **WHEN** `Discover()` iterates the registry
- **THEN** tools are processed in registration order for reproducible output

#### Scenario: Platform-specific paths
- **WHEN** a `ToolParser` is registered
- **THEN** its `Paths` function returns platform-appropriate config locations resolved at call time
