# logging-and-observability Specification

## Purpose
Structured logging with levels, progress reporting, and debug output using stdlib log/slog.

## ADDED Requirements

### Requirement: Structured logging with levels
The system SHALL use `log/slog` for all output beyond report data. `--verbose` SHALL set level to DEBUG. `--quiet` SHALL set level to WARN. Default SHALL be INFO. Report output (table, JSON, SARIF) SHALL go to stdout; all logs SHALL go to stderr.

#### Scenario: Default INFO level
- **WHEN** no verbosity flags are set
- **THEN** INFO and above messages are logged to stderr; DEBUG messages are suppressed

#### Scenario: Verbose mode
- **WHEN** `--verbose` is set
- **THEN** DEBUG messages including raw request/response bodies are logged to stderr

#### Scenario: Quiet mode
- **WHEN** `--quiet` is set
- **THEN** only WARN and ERROR messages are logged to stderr

### Requirement: Progress reporting
The system SHALL display a spinner during config discovery and probe phases. The spinner SHALL cycle every 100ms. A status line SHALL show "Discovering configs...", "Probing N servers...", or "Analyzing responses...". The spinner SHALL be cleared on completion.

#### Scenario: Spinner during probing
- **WHEN** dynamic probing is in progress
- **THEN** stderr shows a cycling spinner with "Probing 5 servers..." status line

#### Scenario: Spinner cleared on completion
- **WHEN** probing completes
- **THEN** the spinner line is cleared and summary is printed

### Requirement: Debug logging
The system SHALL support `--debug` flag that enables source file location in log lines and logs raw JSON-RPC request/response payloads at DEBUG level.

#### Scenario: Debug with source locations
- **WHEN** `--debug` is set
- **THEN** log lines include source file and line number
