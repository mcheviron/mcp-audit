## Why

mcp-scan v2.0.2 provides a dedicated `sbom` subcommand generating CycloneDX and SPDX SBOMs for MCP server inventories. mcp-audit discovers MCP server packages across config files and scans them for vulnerabilities but cannot export a standardized Software Bill of Materials. SBOMs are increasingly required by procurement policies, executive orders, and compliance frameworks. The `.goreleaser.yaml` already generates an SPDX SBOM for mcp-audit's own release — but users cannot generate SBOMs for their MCP server inventory.

## What Changes

- Add `mcp-audit sbom` subcommand that generates CycloneDX 1.6 and SPDX 2.3 SBOMs from discovered MCP server configurations
- SBOM includes: discovered MCP packages (name, version, publisher), transport type, tool count, tool names, and CVE findings if `--with-cves` is set
- Output formats: JSON (CycloneDX default), tag-value (SPDX default), with `--format cyclonedx-json | cyclonedx-xml | spdx-json | spdx-tag` flag
- SBOM generation runs purely from static config discovery — no network probes needed

## Capabilities

### New Capabilities

- `sbom-generation`: CycloneDX 1.6 and SPDX 2.3 Software Bill of Materials generation from discovered MCP server configurations

### Modified Capabilities

(None — pure addition)

## Impact

- `cmd/mcp-audit/main.go` — new `sbom` subcommand
- `internal/sbom/` — new `sbom.go` (CycloneDX JSON/XML and SPDX JSON/tag-value generation), `sbom_test.go`
- `internal/config/discover.go` — reused for MCP server inventory
- No external dependencies; SBOM formats are simple JSON/XML/tag-value output
- CycloneDX and SPDX schemas implemented as Go structs with JSON marshaling

## Non-goals

- Container image or filesystem SBOMs — MCP server inventory only
- SBOM signing or attestation
- SBOM diff/comparison between scans
- Dependency graph resolution beyond MCP server packages (no recursive npm/pip dependency resolution)
- SPDX 3.0 — start with 2.3 which is more widely supported
