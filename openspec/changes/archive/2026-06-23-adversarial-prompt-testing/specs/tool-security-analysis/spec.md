## MODIFIED Requirements

### Requirement: Tool description analysis
The system SHALL inspect every `Tool.Description` field returned by `tools/list`. Before regex-based pattern matching, descriptions SHALL pass through the deobfuscation pipeline (Unicode tag stripping, BiDi detection, zero-width scanning, Base64 decoding, TR39 confusable detection). The deobfuscated output SHALL then be analyzed by the existing regex pipeline. Flagged descriptions SHALL be reported at INFO severity. Deobfuscation-stage findings (BiDi, hidden tags) SHALL be reported at their respective severities independent of the regex results.

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

#### Scenario: URL in description detected (existing behavior)
- **WHEN** a tool description (post-deobfuscation) contains a URL not matching the server's own origin
- **THEN** an INFO finding reports "tool description references external URL: <url>"
