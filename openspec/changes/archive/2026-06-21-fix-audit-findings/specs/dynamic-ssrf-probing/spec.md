## ADDED Requirements

### Requirement: Overall scan timeout
The system SHALL enforce an overall timeout on the dynamic probe phase computed as `(per-probe-timeout-seconds * concurrency) + 30 seconds`. If the probe phase exceeds this timeout, remaining probes SHALL be cancelled and the errgroup error SHALL be returned to the caller.

#### Scenario: Scan completes within timeout
- **WHEN** dynamic probing completes within the overall timeout
- **THEN** all probe results are collected and returned normally

#### Scenario: Scan exceeds overall timeout
- **WHEN** dynamic probing takes longer than the computed overall timeout
- **THEN** remaining probe goroutines are cancelled and a timeout error is returned alongside partial results

### Requirement: Errgroup error propagation
The system SHALL surface errgroup errors from `runDirectProbes` and `runMCPProbes` to the caller instead of debug-logging them. The `Probe()` function SHALL return the first errgroup error if one occurs.

#### Scenario: Probe group error surfaced
- **WHEN** an errgroup worker in `runMCPProbes` returns an error
- **THEN** `g.Wait()` returns that error, and `Probe()` returns it to the CLI layer

#### Scenario: Partial results with errors
- **WHEN** some probes succeed and an errgroup error occurs
- **THEN** the scan returns both the successfully collected findings and the error

### Requirement: Callback listener bind failure detection
The system SHALL report a bind failure when starting the blind SSRF callback listener. If the listener cannot bind to the specified port, an INFO finding SHALL be recorded noting that blind SSRF detection is disabled for this scan run. Probes SHALL continue without callback URLs when the listener is unavailable.

#### Scenario: Callback listener binds successfully
- **WHEN** the callback port is available
- **THEN** a local HTTP listener starts and callback URLs are injected into tool call arguments

#### Scenario: Callback listener bind failure
- **WHEN** the callback port is already in use
- **THEN** an INFO finding is recorded: "callback listener could not bind to port N — blind SSRF detection disabled for this scan"
- **AND** probing continues without callback URLs
