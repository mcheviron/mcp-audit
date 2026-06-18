# static-config-scanning Delta Specification

## MODIFIED Requirements

### Requirement: Config file parsing
The system SHALL parse discovered MCP config files and extract server entries with their `command`, `args`, `url`, `env`, `headers`, and `package` fields. `env` and `headers` fields SHALL be preserved in `ServerEntry` for credential scanning and transport auth configuration. `env` and `headers` values of non-string JSON types (number, bool) SHALL be coerced to strings so they can be scanned and passed to transports.

#### Scenario: Env block extracted
- **WHEN** a config file contains `"mcpServers": {"myserver": {"command": "npx", "args": ["-y", "pkg"], "env": {"NODE_ENV": "production"}}}`
- **THEN** `ServerEntry.Env` contains `{"NODE_ENV": "production"}`

#### Scenario: Headers extracted
- **WHEN** a config file contains `"mcpServers": {"myserver": {"url": "https://example.com", "headers": {"x-api-key": "test"}}}`
- **THEN** `ServerEntry.Headers` contains `{"x-api-key": "test"}`

#### Scenario: Legacy config without env/headers
- **WHEN** a config file does not contain `env` or `headers` fields
- **THEN** `ServerEntry.Env` and `ServerEntry.Headers` are nil
