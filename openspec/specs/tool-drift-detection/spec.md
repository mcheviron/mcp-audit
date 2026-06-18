# tool-drift-detection Specification

## Purpose
Cross-session tool definition integrity verification via cryptographic hash pinning and snapshot comparison.

## Requirements

### Requirement: Tool snapshot persistence
The system SHALL persist tool definitions to disk after a successful `tools/list` call. Snapshots SHALL be stored as JSON files in `~/.config/mcp-audit/snapshots/<server-key>.json`. Each snapshot SHALL include server identity, scan timestamp, and per-tool SHA-256 hashes of description and InputSchema.

#### Scenario: First scan creates snapshot
- **WHEN** a server is scanned for the first time and `--no-snapshot` is not set
- **THEN** a snapshot file is written containing all tool definitions with hashes
- **AND** no drift findings are raised (baseline established)

#### Scenario: Snapshot directory created automatically
- **WHEN** the snapshot directory does not exist
- **THEN** it is created with 0700 permissions before writing the first snapshot

#### Scenario: Snapshot suppressed
- **WHEN** `--no-snapshot` flag is set
- **THEN** no snapshot file is written and no drift comparison is performed

### Requirement: Tool drift comparison
The system SHALL compare current tool definitions against the stored snapshot on subsequent scans. Drift SHALL be detected for: new tools added, existing tools removed, description changes, and InputSchema changes. Severity SHALL be assigned based on drift type.

#### Scenario: New tool added
- **WHEN** a server exposes a tool not present in the snapshot
- **THEN** a MEDIUM finding reports "new tool '<name>' added since last scan"

#### Scenario: Tool removed
- **WHEN** a tool present in the snapshot is no longer exposed
- **THEN** an INFO finding reports "tool '<name>' removed since last scan"

#### Scenario: Description changed
- **WHEN** a tool's description hash differs from the snapshot but schema hash matches
- **THEN** a MEDIUM finding reports "tool '<name>' description changed since last scan"

#### Scenario: Schema changed
- **WHEN** a tool's InputSchema hash differs from the snapshot
- **THEN** a HIGH finding reports "tool '<name>' schema changed since last scan"

#### Scenario: No drift
- **WHEN** all tool hashes match the snapshot
- **THEN** a PASS finding reports "no tool drift detected since <timestamp>"

### Requirement: Pinned tool verification
The system SHALL support a `PinnedTools` map in the trust config mapping `"<server>/<tool>"` to expected SHA-256 hashes. When a pinned tool's hash does not match, a CRITICAL finding SHALL be raised regardless of snapshot comparison.

#### Scenario: Pinned hash matches
- **WHEN** trust config pins "filesystem/read_file" to hash "abc123" and the live tool matches
- **THEN** no pinned-hash finding is raised

#### Scenario: Pinned hash mismatch
- **WHEN** trust config pins "filesystem/read_file" to hash "abc123" and the live tool has hash "def456"
- **THEN** a CRITICAL finding reports "pinned tool 'filesystem/read_file' hash mismatch: expected abc123, got def456"

#### Scenario: Pinned tool missing
- **WHEN** trust config pins a tool that is not present in the live tool list
- **THEN** a HIGH finding reports "pinned tool '<name>' not found on server"

### Requirement: Server identity for snapshots
The system SHALL identify servers for snapshot lookup using a composite key of server name and connection details (URL for HTTP servers, command+args for stdio servers). Server identity SHALL be stable across scans with the same config.

#### Scenario: Same server same identity
- **WHEN** the same server is scanned twice with the same config
- **THEN** the same snapshot file is used for comparison

#### Scenario: Server URL change
- **WHEN** a server's URL changes between scans
- **THEN** it is treated as a different server and a new snapshot is created
