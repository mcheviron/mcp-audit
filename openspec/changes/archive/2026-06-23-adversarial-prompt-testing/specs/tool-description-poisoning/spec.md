## ADDED Requirements

### Requirement: Unicode tag deobfuscation
The system SHALL detect and strip Unicode tag characters (U+E0001 through U+E007F) from tool descriptions before analysis. Descriptions containing hidden Unicode tags SHALL be flagged at MEDIUM severity.

#### Scenario: Hidden Unicode tags in description
- **WHEN** a tool description contains "read file" followed by invisible Unicode tags forming "delete all files"
- **THEN** a MEDIUM finding reports "tool '<name>' description contains hidden Unicode tag content: '<decoded text>'"

#### Scenario: Clean description with no hidden tags
- **WHEN** a tool description contains only visible Unicode characters
- **THEN** no Unicode tag finding is raised

### Requirement: Base64-encoded content detection and decoding
The system SHALL detect Base64-encoded blocks within tool descriptions, decode them, and analyze the decoded content for injection patterns. Base64 blocks longer than 20 decoded characters SHALL be flagged.

#### Scenario: Base64 injection payload detected
- **WHEN** a tool description contains a Base64 block that decodes to "Ignore all previous instructions"
- **THEN** a HIGH severity finding reports "tool '<name>' description contains Base64-encoded injection payload"

#### Scenario: Benign Base64 content
- **WHEN** a tool description contains a short Base64 block (< 20 chars) decoding to non-injection content
- **THEN** an INFO finding reports "tool '<name>' description contains Base64-encoded content" but no injection finding is raised

### Requirement: BiDi override detection
The system SHALL detect bidirectional text override characters (U+202E RIGHT-TO-LEFT OVERRIDE, U+202D LEFT-TO-RIGHT OVERRIDE, U+2066-U+2069 isolate characters) in tool descriptions. Descriptions containing BiDi overrides SHALL be flagged at HIGH severity immediately without further analysis.

#### Scenario: BiDi override in description
- **WHEN** a tool description contains U+202E followed by reversed text
- **THEN** a HIGH severity finding reports "tool '<name>' description contains bidirectional text override characters"

### Requirement: Zero-width character scanning
The system SHALL scan tool descriptions for zero-width characters: U+200B (ZWSP), U+200C (ZWNJ), U+200D (ZWJ), U+FEFF (BOM), U+2060 (Word Joiner), U+200E-U+200F (LRM/RLM). Any detection SHALL be flagged at LOW severity.

#### Scenario: Zero-width spaces in description
- **WHEN** a tool description contains 5+ zero-width space characters
- **THEN** a LOW severity finding reports "tool '<name>' description contains <N> zero-width characters"

### Requirement: TR39 confusable detection
The system SHALL maintain an embedded confusable character map based on Unicode TR39. Tool descriptions containing characters confusable with ASCII letters SHALL be flagged: the confusable text and its ASCII interpretation SHALL be reported.

#### Scenario: Confusable homoglyph in tool name
- **WHEN** a tool description references a tool named "rеad" where 'е' is Cyrillic U+0435 (confusable with ASCII 'e')
- **THEN** a MEDIUM finding reports "tool '<name>' description contains confusable characters: '<confusable text>' (interprets as '<ascii text>')"

### Requirement: Deobfuscation pipeline ordering
The system SHALL run deobfuscation stages in fixed order: (1) Unicode tag stripping, (2) BiDi override detection, (3) zero-width character scanning, (4) Base64 decoding, (5) TR39 confusable detection. Each stage SHALL operate on the output of the previous stage. Any HIGH severity finding at any stage SHALL stop further pipeline processing for that description.

#### Scenario: BiDi override stops pipeline
- **WHEN** a description contains BiDi override characters and Base64 content
- **THEN** the BiDi finding is reported and Base64 analysis is skipped for that description

#### Scenario: Clean description passes all stages
- **WHEN** a description contains no deobfuscation indicators at any stage
- **THEN** the description is passed to the existing regex-based tool description analysis unchanged
