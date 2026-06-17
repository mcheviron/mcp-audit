# error-handling-and-retry Specification

## Purpose
Structured error types, retry logic with exponential backoff for transient failures.

## ADDED Requirements

### Requirement: Structured error types
The system SHALL define `ProbeError`, `ConfigError`, and `TransportError` types implementing the `error` interface with `Unwrap()` support. All errors SHALL wrap underlying causes. Silently discarded errors (bare `_` assignments) SHALL be eliminated.

#### Scenario: ProbeError with unwrap
- **WHEN** a probe fails with a connection timeout
- **THEN** a `ProbeError` is returned wrapping the underlying `net.Error` with target and server context

#### Scenario: ConfigError with path
- **WHEN** a config file fails to parse
- **THEN** a `ConfigError` is returned wrapping the parse error with the file path

### Requirement: Retry logic
The system SHALL retry transient failures (timeout, connection refused, HTTP 503) up to 3 times with exponential backoff starting at 100ms. Context cancellation SHALL stop retry. Non-transient errors (HTTP 400, 401, 404) SHALL NOT be retried.

#### Scenario: Transient failure retried
- **WHEN** a probe gets "connection refused"
- **THEN** the probe is retried after 100ms, then 200ms, then 400ms

#### Scenario: Non-transient failure not retried
- **WHEN** a probe gets HTTP 401
- **THEN** the probe is not retried and the error is reported immediately

#### Scenario: Context cancellation stops retry
- **WHEN** the context is cancelled during backoff
- **THEN** retry stops immediately and the context error is returned
