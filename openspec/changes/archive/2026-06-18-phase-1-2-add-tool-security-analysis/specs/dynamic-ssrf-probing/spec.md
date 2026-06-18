# dynamic-ssrf-probing Delta Specification

## MODIFIED Requirements

### Requirement: Response analysis
The system SHALL analyze probe responses for indicators of successful SSRF: cloud metadata content, internal HTTP response bodies, redirect chains to internal IPs, connection outcomes, AND prompt injection patterns in tool return values. Prompt injection detection in tool responses SHALL use the same pattern set defined in `tool-security-analysis`.

#### Scenario: Cloud metadata returned — CRITICAL
- **WHEN** a probe response contains AWS access key IDs or IAM role credentials
- **THEN** the finding is classified as CRITICAL severity

#### Scenario: Redirect to internal IP — HIGH
- **WHEN** the server follows a redirect to `http://192.168.1.1/admin` and returns that response body
- **THEN** the finding is classified as HIGH severity

#### Scenario: Connection refused — MEDIUM
- **WHEN** the probe to `http://169.254.169.254/` results in "connection refused"
- **THEN** the finding is classified as MEDIUM severity (firewall likely blocked, but server attempted connection)

#### Scenario: Open redirect detected — LOW
- **WHEN** the server returns a 3xx redirect to an internal IP but the probe does not follow it
- **THEN** the finding is classified as LOW severity (open redirect, no internal data exfiltrated)

#### Scenario: Prompt injection in tool response — HIGH
- **WHEN** a tool response text block contains "Ignore previous instructions", "You are now", or role-switching directives
- **THEN** the finding is classified as HIGH severity with detail "tool '<name>' returned potential prompt injection"

#### Scenario: Clean response with no injection
- **WHEN** a tool response contains no injection patterns and no credential/internal data
- **THEN** the finding is classified as PASS
