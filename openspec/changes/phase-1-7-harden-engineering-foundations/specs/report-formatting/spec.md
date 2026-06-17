# report-formatting Delta Specification

## ADDED Requirements

### Requirement: Remediation guidance
The system SHALL include a remediation field in each finding providing actionable fix guidance. Remediation text SHALL be severity-appropriate and specific to the finding type.

#### Scenario: SSRF remediation
- **WHEN** a CRITICAL SSRF finding is reported
- **THEN** the Remediation field reads "Configure the MCP server to validate and sanitize all user-supplied URLs. Implement an allowlist of permitted outbound destinations. Never pass tool arguments directly to HTTP clients without validation."

#### Scenario: Typosquat remediation
- **WHEN** an INFO typosquat finding is reported
- **THEN** the Remediation field reads "Verify the package name is correct. Consider adding it to the trust config trusted list if legitimate, or the blocked list if malicious."

#### Scenario: PASS finding
- **WHEN** a PASS finding is reported
- **THEN** no remediation field is included (nothing to fix)
