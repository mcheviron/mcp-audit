## MODIFIED Requirements

### Requirement: Tool description analysis
The system SHALL inspect every `Tool.Description` field returned by `tools/list` for prompt injection indicators (Layer 1) AND compute heuristic quality scores (Layer 2). Layer 1 detection SHALL use regex and heuristic patterns as before. Layer 2 SHALL compute description entropy, length adequacy, and content structure scores. Flagged descriptions SHALL be reported at INFO severity with an optional `Score` field. When Layer 2 scoring is enabled (`--heuristic` flag, default true), findings SHALL include a `score` field in the output.

#### Scenario: Hidden system prompt detected
- **WHEN** a tool description contains "You are now", "Ignore previous instructions", or "system:" directives
- **THEN** an INFO finding reports "tool description contains potential prompt injection: <pattern>"

#### Scenario: Role-switching directive detected
- **WHEN** a tool description contains "act as", "you must", "your role is", or "from now on"
- **THEN** an INFO finding reports "tool description contains role-switching language"

#### Scenario: Base64-encoded content detected
- **WHEN** a tool description contains a base64-encoded string longer than 40 characters
- **THEN** an INFO finding reports "tool description contains base64-encoded block"

#### Scenario: URL in description detected
- **WHEN** a tool description contains a URL not matching the server's own origin
- **THEN** an INFO finding reports "tool description references external URL: <url>"

#### Scenario: Clean description with low entropy score
- **WHEN** a tool description contains no injection indicators but has low entropy (< 3.5 bits/char)
- **THEN** an INFO finding reports "tool description has low entropy (score: <N>), possible template-generated content"

#### Scenario: Short description with heuristic score
- **WHEN** a tool description is under 20 characters and contains no injection patterns
- **THEN** an INFO finding reports "tool description quality score: <N> (short)" with the heuristic score

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
