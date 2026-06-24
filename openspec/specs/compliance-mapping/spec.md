# compliance-mapping Specification

## Purpose
Map scan findings to compliance framework controls (SOC 2, NIST AI RMF, OWASP LLM Top-10, MITRE ATLAS, EU AI Act) using embedded JSON mappings. Support framework filtering and compliance summary output.

## Requirements

### Requirement: Finding-to-control mapping
The system SHALL map each scan finding to relevant compliance framework controls based on finding type and severity. Mappings SHALL be defined in embedded JSON files per framework. The mapping SHALL be added as a `compliance` field on each finding in the output.

#### Scenario: Credential finding maps to SOC 2 CC6.1
- **WHEN** a CRITICAL severity credential finding is reported
- **THEN** the finding includes `compliance: [{framework: "SOC 2", control: "CC6.1"}]`

#### Scenario: Injection finding maps to OWASP LLM Top-10 LLM01
- **WHEN** a prompt injection finding is reported
- **THEN** the finding includes `compliance: [{framework: "OWASP LLM Top-10", control: "LLM01: Prompt Injection"}]`

### Requirement: Framework filtering
The system SHALL support `--compliance-framework <name>` flag accepting framework short names: `soc2`, `nist-ai-rmf`, `owasp-llm`, `mitre-atlas`, `eu-ai-act`. When set, output SHALL include only findings mapped to the specified framework. When `all` is specified (default), all findings are shown with their compliance tags.

#### Scenario: OWASP-only output
- **WHEN** `--compliance-framework owasp-llm` is set
- **THEN** only findings mapped to OWASP LLM Top-10 controls appear in output

#### Scenario: Multiple frameworks
- **WHEN** `--compliance-framework soc2,owasp-llm` is set
- **THEN** findings mapped to either SOC 2 or OWASP LLM Top-10 appear in output

### Requirement: Supported frameworks
The system SHALL include embedded compliance mappings for: SOC 2 (CC6.1, CC6.6, CC6.7, CC7.1), NIST AI RMF (GOVERN 1.2, MAP 2.1, MEASURE 2.3, MANAGE 4.1), OWASP LLM Top-10 (LLM01, LLM02, LLM05, LLM06, LLM08), MITRE ATLAS (AML.T0000, AML.T0051, AML.T0054), and EU AI Act (Article 9, Article 15, Article 24).

#### Scenario: All frameworks loaded
- **WHEN** mcp-audit starts
- **THEN** all 5 embedded compliance frameworks are loaded and available for mapping

### Requirement: Compliance summary in scan output
The system SHALL include a compliance summary section in scan output showing finding counts per framework per control, enabling quick assessment of regulatory coverage.

#### Scenario: Summary after scan
- **WHEN** a scan completes with 5 CRITICAL and 3 HIGH findings
- **THEN** the compliance summary shows each framework with control IDs and count of findings mapped to each control
