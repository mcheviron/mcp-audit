# toml-config-parsing Specification

## Purpose
Parse MCP server configurations from TOML-format files, extracting server entries with the same shape as JSON parsers produce.

## Requirements

### Requirement: Parse Codex-style TOML MCP config
The system SHALL parse TOML files containing `[mcp_servers]` sections and extract `ServerEntry` values for each server. Each server block SHALL be identified by a section header `[mcp_servers.<name>]`.

#### Scenario: Stdio server
- **WHEN** a TOML file contains `[mcp_servers.my-server]` with `command = "npx"`, `args = ["-y", "@scope/pkg"]`
- **THEN** the parser extracts name=`my-server`, transport=`stdio`, command=`npx`, package=`@scope/pkg`

#### Scenario: Streamable HTTP server
- **WHEN** a TOML file contains `[mcp_servers.remote]` with `url = "https://example.com/mcp"`
- **THEN** the parser extracts name=`remote`, transport=`sse`, url=`https://example.com/mcp`

#### Scenario: Server with auth env var
- **WHEN** a TOML file contains `bearer_token_env_var = "API_TOKEN"` in a server block
- **THEN** the parser extracts the auth token value from the environment variable and sets `AuthToken`

#### Scenario: Server with custom headers
- **WHEN** a TOML file contains `http_headers = { X-Custom = "value" }` in a server block
- **THEN** the parser extracts `Headers` map containing `{"X-Custom": "value"}`

#### Scenario: Server with env vars
- **WHEN** a TOML file contains `env = { NODE_ENV = "production", PORT = "3000" }` in a server block
- **THEN** the parser extracts `Env` map containing `{"NODE_ENV": "production", "PORT": "3000"}`

#### Scenario: Malformed TOML
- **WHEN** a TOML file cannot be parsed (syntax error)
- **THEN** the parser returns an error describing the parse failure with line number

#### Scenario: Empty TOML config
- **WHEN** a TOML file contains no `[mcp_servers]` sections
- **THEN** the parser returns an empty server list with no error

### Requirement: TOML to ServerEntry field mapping
The system SHALL map TOML server fields to `ServerEntry` fields identically to how JSON parsers map equivalent fields. `command` SHALL map to `Command`, `args` to `Args`, `url` to `URL`, `bearer_token_env_var` to `AuthToken` (resolved from env), `http_headers` to `Headers`, `env` to `Env`.

#### Scenario: Field mapping completeness
- **WHEN** a TOML server block has all optional fields (`command`, `args`, `url`, `bearer_token_env_var`, `http_headers`, `env`)
- **THEN** every field is present on the resulting `ServerEntry`

### Requirement: TOML config path discovery
The system SHALL discover Codex TOML config files at platform-appropriate paths: `~/.codex/config.toml` (global) and `.codex/config.toml` (project-scoped, relative to working directory).

#### Scenario: macOS global path
- **WHEN** running on macOS
- **THEN** the global config path resolves to `~/Library/Application Support/Codex/config.toml`

#### Scenario: Linux global path
- **WHEN** running on Linux
- **THEN** the global config path resolves to `~/.codex/config.toml`
