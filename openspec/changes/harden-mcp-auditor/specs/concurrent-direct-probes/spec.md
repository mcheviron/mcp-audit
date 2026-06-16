## ADDED Requirements

### Requirement: Concurrent HTTP probe execution
The system SHALL execute direct HTTP probes concurrently using bounded parallelism with a maximum of 10 in-flight requests.

#### Scenario: Single server, 14 targets
- **WHEN** probing a single HTTP server against 14 internal targets
- **THEN** probes are issued concurrently and results are collected without ordering guarantees

#### Scenario: Three servers, 42 total probes
- **WHEN** three HTTP servers are discovered
- **THEN** all 42 probes run concurrently with at most 10 in-flight at any time

#### Scenario: Probe failure isolation
- **WHEN** one probe hangs or errors
- **THEN** other probes continue unaffected and the error is recorded per-probe
