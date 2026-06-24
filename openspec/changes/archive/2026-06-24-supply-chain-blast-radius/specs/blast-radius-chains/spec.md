## ADDED Requirements

### Requirement: BFS blast-radius chain computation
The system SHALL compute impact chains from CVE findings via breadth-first search: CVE → affected package → MCP server → agent configuration file → tools exposed → credential findings (if any). Chain depth SHALL be configurable via `--blast-radius-depth` (default 3, max 5). The chain SHALL be computed at the end of each scan after all CVE, credential, and tool analysis results are available.

#### Scenario: 3-hop chain from CVE to credentials
- **WHEN** a CVE exists in package `filesystem-server`, an MCP config uses that package and exposes a tool `read_file`, and that tool returned AWS credentials during probing
- **THEN** the blast-radius chain shows: CVE → filesystem-server → config.json → read_file → AWS credentials

#### Scenario: Chain truncated at max depth
- **WHEN** `--blast-radius-depth 2` is set and a full chain would be 4 hops
- **THEN** the chain stops at hop 2 with a `truncated: true` marker

#### Scenario: No CVE findings produces empty chains
- **WHEN** a scan produces no CVE findings
- **THEN** the blast-radius output is an empty list

### Requirement: Chain output format
The system SHALL output blast-radius chains as JSON arrays of hops. Each hop SHALL include `type` (cve/package/server/agent/tool/credential), `id`, `label`, and `severity` (if applicable). The full chain SHALL include a `max_severity` field reflecting the most severe finding in the chain.

#### Scenario: Chain in JSON output
- **WHEN** `--format json --blast-radius` is used
- **THEN** the JSON output includes a `blastRadiusChains` array with each chain's hops and `max_severity`

#### Scenario: Chain in table output
- **WHEN** `--blast-radius` is used with table output
- **THEN** each chain is displayed as an indented tree showing hop type and label

### Requirement: Chain cross-references in CVE findings
The system SHALL add a `related_findings` field to each CVE Result listing the IDs of credential findings, tool capability classifications, and shadowing detections linked to the affected server. This field SHALL be populated even when `--blast-radius` is not explicitly set.

#### Scenario: CVE finding links to credential finding
- **WHEN** a CVE finding on server `filesystem` and a credential finding from the same server coexist in results
- **THEN** the CVE finding's `related_findings` includes the credential finding ID
