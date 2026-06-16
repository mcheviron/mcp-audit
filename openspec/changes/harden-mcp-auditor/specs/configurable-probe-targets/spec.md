## ADDED Requirements

### Requirement: CLI-configurable probe targets
The system SHALL accept a `--targets` flag containing a comma-separated list of URLs to use as probe targets, overriding the built-in default list.

#### Scenario: Default targets
- **WHEN** `--targets` is not specified
- **THEN** the 14 built-in internal/metadata endpoints are used

#### Scenario: Custom targets override defaults
- **WHEN** `--targets http://127.0.0.1:8000/,http://10.0.0.5/` is passed
- **THEN** only those two targets are probed; the built-in list is ignored

#### Scenario: Single custom target
- **WHEN** `--targets http://localhost:9090/` is passed
- **THEN** only that target is probed
