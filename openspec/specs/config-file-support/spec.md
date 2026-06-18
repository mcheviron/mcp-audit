# config-file-support Specification

## Purpose
JSON configuration file for persistent settings with CLI flag override.

## Requirements

### Requirement: Config file loading
The system SHALL load settings from `~/.config/mcp-audit/config.json` on startup. CLI flags SHALL override config file values. Missing config file SHALL be silently ignored (not an error).

#### Scenario: Config file loaded
- **WHEN** `~/.config/mcp-audit/config.json` exists with `{"format": "json"}`
- **THEN** the default output format is JSON

#### Scenario: CLI flag overrides config
- **WHEN** config file sets `"format": "json"` and `--format sarif` is passed
- **THEN** the output format is SARIF

#### Scenario: No config file
- **WHEN** `~/.config/mcp-audit/config.json` does not exist
- **THEN** defaults apply for all settings

### Requirement: Config file schema
The system SHALL support these config file keys: `format`, `trust_config`, `targets`, `allow_hosts`, `block_hosts`, `timeout`, `concurrency`, `probe_depth`, `max_response`, `no_color`, `snapshot_dir`. Unknown keys SHALL be ignored with a WARN log.

#### Scenario: Full config
- **WHEN** config file contains all supported keys
- **THEN** all settings are applied as defaults subject to CLI override
