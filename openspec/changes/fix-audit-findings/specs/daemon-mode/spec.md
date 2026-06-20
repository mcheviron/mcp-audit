## ADDED Requirements

### Requirement: Graceful shutdown
The daemon SHALL handle SIGTERM and SIGINT signals by stopping the watch loop and exiting cleanly. The watch command SHALL use `signal.NotifyContext` to derive a cancellation context passed to the watcher's `Watch` method. The watch loop SHALL check `ctx.Done()` at each iteration and return when cancelled.

#### Scenario: SIGTERM stops daemon
- **WHEN** the daemon process receives SIGTERM
- **THEN** the watch loop exits, the interval ticker and poll ticker are stopped, and the process exits with code 0

#### Scenario: In-progress scan completes before exit
- **WHEN** a scan is in progress during shutdown
- **THEN** the daemon waits for the current scan to complete before exiting

#### Scenario: Second signal forces exit
- **WHEN** a second SIGTERM or SIGINT is received during graceful shutdown
- **THEN** the process exits immediately
