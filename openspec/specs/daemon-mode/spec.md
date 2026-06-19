# daemon-mode Specification

## Purpose
Continuous filesystem watching and re-scanning of MCP config files with configurable notification hooks.

## Requirements

### Requirement: Config file watching
The system SHALL watch discovered MCP config file directories for changes using filesystem notifications. On change, the system SHALL re-run static analysis. Changes within a 500ms window SHALL be debounced.

#### Scenario: Config change triggers re-scan
- **WHEN** a watched config file is modified
- **THEN** static analysis re-runs within 500ms of the last write

#### Scenario: New config file detected
- **WHEN** a new MCP config file is created in a watched directory
- **THEN** it is discovered and scanned

### Requirement: Notification hook
The system SHALL support `--on-finding` flag specifying a command to run when new findings are detected. The command SHALL receive the finding count and severity summary as arguments.

#### Scenario: Finding triggers notification
- **WHEN** a re-scan finds a new CRITICAL finding
- **THEN** the command specified by `--on-finding` is executed with finding details

### Requirement: Watch interval
The system SHALL re-scan all known config paths at a configurable interval (`--watch-interval`, default 5m) in addition to reacting to filesystem events.

#### Scenario: Periodic re-scan
- **WHEN** the watch interval elapses with no filesystem events
- **THEN** a static re-scan is performed to catch changes missed by filesystem watchers
