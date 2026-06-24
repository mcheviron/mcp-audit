# heuristic-scoring Specification

## Purpose
Compute heuristic quality and security scores for MCP tool descriptions, naming conventions, and input schemas. Aggregate individual scores into a composite security risk rating and support CI gating via minimum/maximum score thresholds.

## Requirements

### Requirement: Description entropy scoring
The system SHALL compute a description quality score (0-100) for each tool based on: description length below threshold (0-20 chars scores 0, 20-50 scores 50, 50+ scores 100), presence of whitespace-only descriptions (scores 0), and character entropy (Shannon entropy on character distribution, normalized 0-100).

#### Scenario: Empty description scores zero
- **WHEN** a tool description is empty or whitespace-only
- **THEN** the description quality score is 0

#### Scenario: Short description scores low
- **WHEN** a tool description is 15 characters
- **THEN** the description quality score is 0

#### Scenario: Adequate description scores high
- **WHEN** a tool description is 80 characters of natural language
- **THEN** the description quality score is 100

### Requirement: Naming convention consistency scoring
The system SHALL score tool naming consistency (0-100) across all tools returned by a server: tools using a consistent prefix (e.g., `file_read`, `file_write`) score 100; mixed naming conventions (snake_case + camelCase + kebab-case) score proportionally lower based on the ratio of the most common convention.

#### Scenario: Consistent snake_case naming
- **WHEN** all tools use snake_case naming (e.g., `read_file`, `write_file`, `delete_file`)
- **THEN** the naming consistency score is 100

#### Scenario: Mixed naming conventions
- **WHEN** a server exposes tools `readFile`, `get_data`, and `fetch-url`
- **THEN** the naming consistency score is ≤ 50

### Requirement: Schema complexity scoring
The system SHALL compute a schema complexity score (0-100) for each tool based on: number of required parameters (0 = 100, 1-3 = 80, 4-6 = 60, 7+ = 40), presence of `additionalProperties: false` (+20 bonus, capped at 100), and parameter type diversity (string-only = 100, mixed types with `any` = 50).

#### Scenario: Well-constrained schema
- **WHEN** a tool has 2 required string parameters and `additionalProperties: false`
- **THEN** the schema complexity score is 100

#### Scenario: Unbounded schema
- **WHEN** a tool has `additionalProperties: true` and 0 required parameters
- **THEN** the schema complexity score is ≤ 50

### Requirement: Multi-factor risk aggregation
The system SHALL compute a composite security score (0-100) from weighted factors: typosquat distance penalty (weight 0.25), CVE count penalty (weight 0.30), capability breadth penalty (weight 0.20), description quality (weight 0.15), network exposure penalty (weight 0.10). Individual factor scores SHALL each be normalized to 0-100 before weighting. The final score SHALL be `sum(factor_i * weight_i)`.

#### Scenario: Perfect score
- **WHEN** a server has no typosquat matches, no CVEs, minimal capabilities, good description, and no network exposure
- **THEN** the composite security score is 100

#### Scenario: High-risk server
- **WHEN** a server has a typosquat distance of 2, 3 HIGH CVEs, shell capability, and empty description
- **THEN** the composite security score is ≤ 30

### Requirement: CI gate integration
The system SHALL support `--min-security-score <N>` and `--max-absolute-risk <N>` flags on the `scan` and `static` commands. When the computed score is below the minimum or above the maximum, the command SHALL exit with a non-zero exit code and report the failing score.

#### Scenario: Score above minimum passes
- **WHEN** `--min-security-score 60` is set and the lowest server score is 75
- **THEN** the command exits with code 0

#### Scenario: Score below minimum fails
- **WHEN** `--min-security-score 80` is set and a server scores 55
- **THEN** the command exits with code 2 and reports "server <name> score 55 below minimum 80"

#### Scenario: Absolute risk above max fails
- **WHEN** `--max-absolute-risk 40` is set and a server's absolute risk is 65
- **THEN** the command exits with code 2 and reports the violation

### Requirement: Tiered analysis pipeline ordering
The system SHALL execute analysis in tier order: Layer 1 (regex detection, unchanged) SHALL run first. Layer 2 (heuristic scoring) SHALL run on all tools after Layer 1 completes. Layer 2 failures (computation errors) SHALL not block Layer 1 findings from appearing in results.

#### Scenario: Layer 1 and Layer 2 both produce results
- **WHEN** a scan runs against a server with injection patterns in descriptions
- **THEN** the report includes both Layer 1 regex findings AND Layer 2 heuristic scores

#### Scenario: Layer 2 computation error does not hide Layer 1
- **WHEN** heuristic scoring encounters an error parsing a malformed schema
- **THEN** the Layer 1 regex findings are still reported with the Layer 2 score field empty
