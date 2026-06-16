# typosquat-detection Specification

## Purpose
TBD - created by archiving change build-mcp-auditor. Update Purpose after archive.
## Requirements
### Requirement: Levenshtein distance calculation
The system SHALL compute the edit distance between two strings using the standard dynamic programming algorithm with insert, delete, and substitute operations each costing 1.

#### Scenario: Identical strings
- **WHEN** comparing two identical package names
- **THEN** the Levenshtein distance is 0

#### Scenario: One character difference
- **WHEN** comparing "@scope/mcp-server" and "@scope/mcp-serve"
- **THEN** the Levenshtein distance is 1

#### Scenario: Empty string
- **WHEN** comparing any string against an empty string
- **THEN** the Levenshtein distance equals the length of the non-empty string

### Requirement: Known package databases
The system SHALL maintain two embedded lists: a list of known legitimate MCP package names and a list of confirmed malicious MCP package names, both loaded at compile time.

#### Scenario: Legitimate package match
- **WHEN** a discovered server uses package "mcp-server-filesystem" and the legitimate list contains "mcp-server-filesystem"
- **THEN** the package is classified as "known legitimate" and no alert is raised

#### Scenario: Malicious package match
- **WHEN** a discovered server uses a package on the confirmed malicious list
- **THEN** the scanner SHALL raise a CRITICAL severity finding regardless of edit distance

### Requirement: Typosquat detection threshold
The system SHALL flag any package name whose Levenshtein distance to a known legitimate package is ≤ 2 as a potential typosquat at INFO severity.

#### Scenario: Typosquat detected
- **WHEN** a discovered server uses "mcp-server-filesytem" and "mcp-server-filesystem" is in the legitimate list
- **THEN** the scanner reports an INFO finding: "Package X is potential typosquat of Y (distance: 2)"

#### Scenario: Distance too large
- **WHEN** a discovered package name has Levenshtein distance 3 or greater from all known legitimate packages
- **THEN** no typosquat alert is raised for that package

#### Scenario: Package not in either list
- **WHEN** a discovered package name is neither in the legitimate nor malicious lists, and distance to nearest legitimate package exceeds 2
- **THEN** the package is reported with no typosquat finding (PASS)

