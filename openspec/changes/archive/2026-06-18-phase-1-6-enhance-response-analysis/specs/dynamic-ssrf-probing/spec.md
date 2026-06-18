# dynamic-ssrf-probing Delta Specification

## ADDED Requirements

### Requirement: Content-based response scoring
The system SHALL compute a suspicion score (0.0-1.0) for each probe response using keyword-frequency analysis weighted by response size. Responses scoring above 0.7 SHALL trigger deeper regex analysis. Responses scoring below 0.3 SHALL be classified as PASS more aggressively.

#### Scenario: High-suspicion response
- **WHEN** a response contains multiple security-relevant keywords (access_key, token, password, secret) normalized to response size with score >0.7
- **THEN** all credential and metadata regex patterns are applied

### Requirement: Entropy analysis
The system SHALL compute Shannon entropy on response bodies. Entropy above 7.5 SHALL be classified as encrypted/compressed (benign). Entropy below 1.5 with high keyword score SHALL raise a finding.

#### Scenario: Low entropy with metadata
- **WHEN** response entropy <1.5 and metadata pattern matches
- **THEN** a HIGH finding reports "low-entropy metadata response detected"

### Requirement: Response classification
The system SHALL classify responses as metadata, error, data, or binary based on content-type header and body characteristics. Classification SHALL influence subsequent analysis path.

#### Scenario: Metadata response
- **WHEN** response body matches `(?i)(ami-id|instance-id|iam/)` and content-type is text
- **THEN** the response is classified as metadata and analyzed with cloud credential patterns

### Requirement: Timing analysis
The system SHALL record response times per probe and flag outliers. Responses more than 2 standard deviations faster than the mean SHALL be flagged as potential internal-service access.

#### Scenario: Anomalously fast response
- **WHEN** a probe response takes 10ms while the mean for that server is 200ms
- **THEN** an INFO finding reports "anomalously fast response (10ms vs 200ms mean) — possible internal service access"

### Requirement: Configurable response limit
The system SHALL support a `--max-response` flag (default 64KB) to control how much of each response body is read and analyzed. The previous 4KB limit SHALL be removed as a hardcoded constant.

#### Scenario: Custom response limit
- **WHEN** `--max-response 131072` is set
- **THEN** up to 128KB of each response body is read and analyzed
