## MODIFIED Requirements

### Requirement: Composition chain detection
The system SHALL detect paths in the graph where a tool from one server can feed data to a tool from another server. Chains connecting a data-access tool (filesystem, database) to a network-access tool (URL fetch, HTTP post) SHALL produce findings grouped by unique server sequence. Each unique server sequence SHALL produce exactly one finding. The finding severity SHALL be the maximum severity across all tool-level paths in the group, determined by chain length: ≤3 hops = MEDIUM, 4-5 hops = HIGH, >5 hops = CRITICAL. The finding description SHALL name the server sequence and the count of tool-level paths. The detail field SHALL list up to 3 example tool-level paths. When a server sequence has only one tool-level path, no count SHALL be appended to the description.

#### Scenario: Filesystem-to-network chain detected (one path)
- **WHEN** server A has a file-read tool producing text, and server B has a URL-fetch tool accepting URLs
- **THEN** a MEDIUM finding reports "potential data exfiltration chain: <server A> -> <server B>"
- **AND** the detail field contains the single tool-level path

#### Scenario: Multiple tool-level paths grouped by server sequence
- **WHEN** 50 tool-level paths exist for the server sequence `datagouv -> openaiDeveloperDocs -> datagouv`
- **THEN** a single finding reports "long composition chain (5 hops): datagouv -> openaiDeveloperDocs -> datagouv -> openaiDeveloperDocs -> datagouv (50 tool-level paths found)"
- **AND** the detail field contains up to 3 example tool-level paths
- **AND** no other finding exists for the same server sequence

#### Scenario: No chain
- **WHEN** no path exists between any data-access tool and any network-access tool
- **THEN** no composition chain findings are raised

#### Scenario: Mixed-length chains grouped by max severity
- **WHEN** a server sequence has 3 hops (MEDIUM) for some tool paths and 5 hops (HIGH) for others
- **THEN** the finding severity is HIGH
- **AND** the finding description includes the longest chain length observed
