# tool-security-analysis Specification

## Purpose
Static and dynamic analysis of MCP tool descriptions, input schemas, and return values for prompt injection, dangerous capabilities, tool shadowing, and information hiding.
## Requirements
### Requirement: Tool description analysis
The system SHALL inspect every `Tool.Description` field returned by `tools/list` for prompt injection indicators (Layer 1) AND compute heuristic quality scores (Layer 2). Layer 1 detection SHALL use regex and heuristic patterns. Before regex-based pattern matching, descriptions SHALL pass through the deobfuscation pipeline (Unicode tag stripping, BiDi detection, zero-width scanning, Base64 decoding, TR39 confusable detection). The deobfuscated output SHALL then be analyzed by the existing regex pipeline. Flagged descriptions SHALL be reported at INFO severity with an optional `Score` field. Deobfuscation-stage findings (BiDi, hidden tags) SHALL be reported at their respective severities independent of the regex results. When Layer 2 scoring is enabled (`--heuristic` flag, default true), findings SHALL include a `score` field in the output.

#### Scenario: Deobfuscation reveals hidden injection
- **WHEN** a tool description contains Base64-encoded "Ignore previous instructions" that the raw regex would miss
- **THEN** the Base64 decode stage decodes it AND the existing regex pipeline detects the injection in the decoded text

#### Scenario: BiDi override caught before regex
- **WHEN** a tool description contains U+202E followed by reversed injection text
- **THEN** the BiDi stage reports HIGH severity and the regex pipeline is skipped for that description

#### Scenario: Clean description passes unchanged
- **WHEN** a tool description contains no deobfuscation indicators
- **THEN** the description passes to the existing regex pipeline with no modifications and behavior matches current implementation

#### Scenario: Hidden system prompt detected (existing behavior)
- **WHEN** a tool description (post-deobfuscation) contains "You are now", "Ignore previous instructions", or "system:" directives
- **THEN** an INFO finding reports "tool description contains potential prompt injection: <pattern>"

#### Scenario: Role-switching directive detected (existing behavior)
- **WHEN** a tool description (post-deobfuscation) contains "act as", "you must", "your role is", or "from now on"
- **THEN** an INFO finding reports "tool description contains role-switching language"

#### Scenario: Base64-encoded content detected
- **WHEN** a tool description contains a base64-encoded string longer than 40 characters
- **THEN** an INFO finding reports "tool description contains base64-encoded block"

#### Scenario: URL in description detected (existing behavior)
- **WHEN** a tool description (post-deobfuscation) contains a URL not matching the server's own origin
- **THEN** an INFO finding reports "tool description references external URL: <url>"

#### Scenario: Clean description passes
- **WHEN** a tool description contains no injection indicators
- **THEN** no finding is raised for that description

#### Scenario: Clean description with low entropy score
- **WHEN** a tool description contains no injection indicators but has low entropy (< 3.5 bits/char)
- **THEN** an INFO finding reports "tool description has low entropy (score: <N>), possible template-generated content"

#### Scenario: Short description with heuristic score
- **WHEN** a tool description is under 20 characters and contains no injection patterns
- **THEN** an INFO finding reports "tool description quality score: <N> (short)" with the heuristic score

### Requirement: Tool capability classification
The system SHALL parse `Tool.InputSchema` to classify tool capabilities into categories: filesystem, network, shell, database, and unknown. Tools with dangerous capabilities SHALL be reported at INFO severity with the capability list.

#### Scenario: Filesystem tool detected
- **WHEN** InputSchema contains properties with names "path", "file", or "directory" of type string
- **THEN** the tool is classified as filesystem-capable and an INFO finding lists "filesystem access"

#### Scenario: Network tool detected
- **WHEN** InputSchema contains properties with names "url", "uri", "endpoint", or "host" of type string
- **THEN** the tool is classified as network-capable

#### Scenario: Shell tool detected
- **WHEN** InputSchema contains properties with names "command", "cmd", or "script" of type string
- **THEN** the tool is classified as shell-capable and flagged at HIGH severity

#### Scenario: Multi-capability tool
- **WHEN** a tool is classified as both network-capable and shell-capable
- **THEN** an INFO finding notes "tool has multiple capability classes: network, shell"

#### Scenario: Overly broad schema
- **WHEN** InputSchema has no `properties` field or `additionalProperties` is true with no constraints
- **THEN** an INFO finding reports "tool schema is overly broad, accepts unrestricted input"

### Requirement: Tool shadowing detection
The system SHALL detect when two or more servers expose tools with the same name. When same-named tools have different descriptions or schemas, the system SHALL report a MEDIUM severity finding. When same-named tools have identical descriptions, the system SHALL report an INFO severity finding for potential impersonation. Shadowing detection SHALL operate within a single scan session (in-memory comparison, no persistent storage).

#### Scenario: Same-name tools with different descriptions
- **WHEN** server A exposes tool "fetch" with description "Fetch a URL" and server B exposes tool "fetch" with description "Execute system commands"
- **THEN** a MEDIUM finding reports "tool shadowing: 'fetch' exposed by servers A and B with conflicting descriptions"

#### Scenario: Same-name tools with identical definitions
- **WHEN** two servers expose identically-named tools with matching descriptions and schemas
- **THEN** an INFO finding reports "tool '<name>' exposed by servers A and B with identical descriptions — potential impersonation"

#### Scenario: Single-instance tool
- **WHEN** a tool name appears in only one server
- **THEN** no shadowing finding is raised

### Requirement: Tool return value analysis
The system SHALL analyze `CallToolResult.Content` text blocks for prompt injection patterns during dynamic probing (Layer 1) AND compute response quality heuristics (Layer 2). Layer 2 SHALL compute response entropy, size anomalies, and repetition ratios. This analysis SHALL run alongside existing credential and SSRF detection. Findings SHALL be reported at the appropriate severity with an optional `Score` field.

#### Scenario: Prompt injection in tool response
- **WHEN** a tool response contains "Ignore previous instructions" or similar directives
- **THEN** a HIGH severity finding reports "tool '<name>' returned potential prompt injection to AI client"

#### Scenario: Clean tool response
- **WHEN** a tool response contains no injection patterns
- **THEN** no injection finding is raised (existing credential/SSRF checks still apply)

#### Scenario: Anomalously large response
- **WHEN** a tool response exceeds 10KB and contains repetitive content (>50% duplicate lines)
- **THEN** an INFO finding reports "tool '<name>' response is anomalously large (<N> bytes) with high repetition ratio"

### Requirement: Missing description flagging
The system SHALL flag tools with empty or missing descriptions. Empty descriptions are an information-hiding technique used by malicious servers. When heuristic scoring is enabled, missing descriptions SHALL also reduce the server's composite security score.

#### Scenario: Empty description
- **WHEN** a tool has an empty string or whitespace-only description
- **THEN** an INFO finding reports "tool '<name>' has no description (information hiding risk)"

#### Scenario: Description present
- **WHEN** a tool has a non-empty description
- **THEN** no missing-description finding is raised
