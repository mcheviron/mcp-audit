## MODIFIED Requirements

### Requirement: Vertical table layout with per-file sub-headers
The terminal table SHALL group rows within each severity tier by `ConfigPath`. Each distinct config file SHALL be preceded by a sub-header line containing the file path (and `Scope` when set). Rows within a file SHALL print with the finding text word-wrapped to fit the terminal width: the first line SHALL be `<SEVERITY>  <server-padded>  <finding-first-line>`, and continuation lines of the finding SHALL be indented to align with the finding column (same offset as the first line's finding text). `<server-padded>` is right-padded with spaces to the longest server name in the visible severity group. Remediation text SHALL print on its own line, indented to align with the finding text, prefixed with `↳ Remediation:`, and word-wrapped with the same continuation indent. Detail text (if present) SHALL print on its own line, indented like remediation but without a prefix, and word-wrapped with the same continuation indent. When a row has no `ConfigPath`, no sub-header SHALL be printed for it.

#### Scenario: Per-file sub-headers emitted
- **WHEN** 3 PASS findings span 2 different `ConfigPath` values
- **THEN** the output contains 2 sub-header lines, one per file, and each appears exactly once

#### Scenario: Remediation indented under finding
- **WHEN** a finding has a `Remediation` field
- **THEN** the output contains a `↳ Remediation:` line on its own row, indented past the severity+server columns, with the remediation text following

#### Scenario: Server column right-padded
- **WHEN** 3 rows in the same severity group have server names of different lengths
- **THEN** the finding texts all start at the same column offset

#### Scenario: No sub-header for empty config path
- **WHEN** a row has no `ConfigPath`
- **THEN** no sub-header line is printed for that row; the row prints directly under its severity group heading

#### Scenario: Long finding text word-wraps
- **WHEN** a finding's text exceeds the available content width (terminal width minus severity and server columns)
- **THEN** the finding text wraps to continuation lines indented to align with the finding column start
- **AND** words are not split mid-word; wrapping occurs at word boundaries

#### Scenario: Short finding text stays on one line
- **WHEN** a finding's text fits within the available content width
- **THEN** the finding prints on a single line with no wrapping (same behavior as today)
