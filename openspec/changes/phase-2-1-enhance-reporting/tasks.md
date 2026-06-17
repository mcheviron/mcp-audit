## 1. SARIF enhancements

- [ ] 1.1 Add `taxa` section to SARIF output with CWE-918, CWE-200, CWE-350, CWE-506 entries
- [ ] 1.2 Add `reportingDescriptor` per rule with `helpUri` pointing to OWASP MCP Top 10
- [ ] 1.3 Include PASS results as `note` level in SARIF output

## 2. JUnit XML output

- [ ] 2.1 Create `internal/report/junit.go` with JUnit XML writer
- [ ] 2.2 Map findings to `<testcase>`, `<failure>`, `<error>`, `<skipped>` elements
- [ ] 2.3 Add `junit` to `ResolveFormat` in format.go

## 3. JSON metadata

- [ ] 3.1 Wrap JSON findings array in object with `tool`, `version`, `scan_time`, `summary` fields
- [ ] 3.2 Include RFC3339 scan timestamp
- [ ] 3.3 Include summary counts (critical, high, medium, low, info, pass, servers_scanned)

## 4. Table grouping

- [ ] 4.1 Group findings by severity with headers between groups
- [ ] 4.2 Add summary header line before findings with count per severity
- [ ] 4.3 Add blank line between severity groups for readability

## 5. Exit code granularity

- [ ] 5.1 Update `ExitCode` in format.go: 0=clean, 1=CRITICAL, 2=HIGH, 3=MEDIUM, 4=error
- [ ] 5.2 Wire new exit codes into `main()` for both static and probe commands

## 6. Tests

- [ ] 6.1 Test SARIF output includes taxa section and reporting descriptors
- [ ] 6.2 Test JUnit output validates against JUnit XSD
- [ ] 6.3 Test JSON output includes metadata and summary
- [ ] 6.4 Test table output groups by severity
- [ ] 6.5 Test exit codes for each severity level
