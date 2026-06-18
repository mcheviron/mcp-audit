# finding-deduplication Specification

## Purpose
Merge duplicate findings within a scan run by matching server, type, and normalized finding text.

## Requirements

### Requirement: Finding deduplication
The system SHALL deduplicate findings after all probes and analysis complete, before report output. Two findings with the same Server, Type, and normalized Finding (case-insensitive, whitespace-collapsed) SHALL be merged. The merged finding SHALL retain the highest severity and concatenate unique Detail fields.

#### Scenario: Duplicate findings merged
- **WHEN** two findings both have Server="my-server", Type="dynamic", Finding="no SSRF detected for http://127.0.0.1/"
- **THEN** only one finding appears in output with the highest severity

#### Scenario: Same server different target
- **WHEN** findings differ in Finding text because they reference different probe targets
- **THEN** both findings are preserved (not deduplicated)

#### Scenario: Severity escalation on merge
- **WHEN** duplicate findings have severities PASS and HIGH
- **THEN** the merged finding has severity HIGH
