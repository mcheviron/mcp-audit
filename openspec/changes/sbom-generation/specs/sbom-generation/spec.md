## ADDED Requirements

### Requirement: SBOM subcommand
The system SHALL provide an `sbom` subcommand that discovers MCP server configurations and generates a Software Bill of Materials. The subcommand SHALL accept `--format` flag with values `cyclonedx-json` (default), `cyclonedx-xml`, `spdx-json`, `spdx-tag`.

#### Scenario: Default CycloneDX JSON output
- **WHEN** `mcp-audit sbom` is run
- **THEN** the output is CycloneDX 1.6 JSON written to stdout

#### Scenario: SPDX tag-value output
- **WHEN** `mcp-audit sbom --format spdx-tag` is run
- **THEN** the output is SPDX 2.3 tag-value format written to stdout

### Requirement: SBOM component listing
The generated SBOM SHALL include one component per discovered MCP server. Each component SHALL include: `name` (package name), `version` (from config, or "unknown"), `supplier` (from trust config publisher field if available), `type: "application"`, and `description` (transport type + tool count).

#### Scenario: Component with full metadata
- **WHEN** a discovered MCP server has name `filesystem`, version `1.2.0`, and publisher `Anthropic` from trust config
- **THEN** the SBOM component shows name=`filesystem`, version=`1.2.0`, supplier=`Anthropic`

#### Scenario: Component with minimal metadata
- **WHEN** a discovered MCP server has only a package name with no version or publisher info
- **THEN** the SBOM component shows version=`unknown` and no supplier

### Requirement: CVE inclusion in SBOM
The system SHALL support `--with-cves` flag on the `sbom` subcommand. When set, the system SHALL query CVE databases for each discovered package and include vulnerability entries in the SBOM output (CycloneDX `vulnerabilities` array, SPDX external reference with `SECURITY` category).

#### Scenario: CVE included in CycloneDX SBOM
- **WHEN** `mcp-audit sbom --with-cves` is run and package `filesystem` has CVE-2025-1234
- **THEN** the CycloneDX JSON includes a `vulnerabilities` array with CVE-2025-1234 linked to the `filesystem` component via bom-ref

#### Scenario: SBOM without CVEs
- **WHEN** `mcp-audit sbom` is run without `--with-cves`
- **THEN** no CVE data is included and no network calls are made

### Requirement: SBOM metadata
The generated SBOM SHALL include metadata: tool name (`mcp-audit`), tool version (build version), timestamp (ISO 8601), and the format specification version (CycloneDX 1.6 or SPDX 2.3).

#### Scenario: Metadata present in CycloneDX output
- **WHEN** `mcp-audit sbom` is run
- **THEN** the output includes `"metadata": {"tools": [{"name": "mcp-audit", "version": "<version>"}]}` and `"serialNumber"` with a UUID

### Requirement: Output file support
The system SHALL support `--output <path>` flag to write the SBOM to a file instead of stdout. File extension SHALL match the selected format (`.json` for CycloneDX/SPDX JSON, `.xml` for CycloneDX XML, `.spdx` for SPDX tag-value).

#### Scenario: Output to file
- **WHEN** `mcp-audit sbom --output sbom.json` is run
- **THEN** the CycloneDX JSON SBOM is written to `sbom.json` and a confirmation message is printed to stderr

### Requirement: Empty inventory handling
When no MCP server configurations are discovered, the system SHALL generate a valid minimal SBOM with no components and exit with code 0.

#### Scenario: No configs found
- **WHEN** `mcp-audit sbom` is run in a directory with no MCP config files
- **THEN** a valid CycloneDX JSON SBOM is output with an empty `components` array and exit code 0
