## MODIFIED Requirements

### Requirement: Terminal table output (default)
The system SHALL output scan results as a formatted terminal table by default, with columns for severity, server name, and finding description. The system SHALL propagate I/O errors from all write operations. If any `Fprintf` call to the output writer fails, the table writer SHALL return the error immediately.

#### Scenario: Default output format
- **WHEN** user runs `mcp-audit scan` with no format flag
- **THEN** results are displayed as an aligned text table with severity, server, and finding columns

#### Scenario: Color-coded severity
- **WHEN** output is to a TTY
- **THEN** CRITICAL findings are red, HIGH are yellow, MEDIUM are cyan, LOW are blue, INFO are dim, PASS are green

#### Scenario: Write error propagated
- **WHEN** the output writer returns an error during table formatting (e.g., broken pipe)
- **THEN** the table writer returns the error instead of silently discarding it
