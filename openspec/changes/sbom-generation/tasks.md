## 1. CycloneDX data model

- [x] 1.1 Define CycloneDX 1.6 Go structs in `internal/sbom/cyclonedx.go`: Bom, Metadata, Tool, Component, Vulnerability, Rating, Affect, Supplier
- [x] 1.2 Implement `NewCycloneDX(inventory []DiscoveredServer, cves map[string][]CVEResult, version string) Bom` populating Bom with metadata, components, and optional vulnerabilities
- [x] 1.3 Implement `Bom.ToJSON() ([]byte, error)` and `Bom.ToXML() ([]byte, error)` marshaling
- [x] 1.4 Write unit tests in `internal/sbom/sbom_test.go`: valid CycloneDX 1.6 JSON output, matching specVersion and bomFormat, component count matches inventory, CVE inclusion when provided

## 2. SPDX data model

- [x] 2.1 Define SPDX 2.3 Go structs in `internal/sbom/spdx.go`: Document, CreationInfo, Package, ExternalRef, Checksum, Supplier
- [x] 2.2 Implement `NewSPDX(inventory []DiscoveredServer, cves map[string][]CVEResult, version string) Document` populating SPDX document with packages and external references
- [x] 2.3 Implement `Document.ToJSON() ([]byte, error)` and `Document.ToTagValue() ([]byte, error)` serialization
- [x] 2.4 Write unit tests: valid SPDX 2.3 JSON output, correct SPDXID format, tag-value format contains expected headers, CVE external references when provided

## 3. SBOM subcommand

- [x] 3.1 Add `cmd/mcp-audit/main_sbom.go` implementing `sbom` subcommand: runs `config.Discover()`, builds inventory, optionally runs CVE scan, formats output per `--format` flag, writes to stdout or `--output` file
- [x] 3.2 Add `--format`, `--with-cves`, `--output`, `--config-root` flags to sbom subcommand
- [x] 3.3 Write unit test in `cmd/mcp-audit/main_sbom_test.go`: sbom subcommand produces valid CycloneDX JSON, `--format spdx-json` produces valid SPDX JSON, `--output` writes to file

## 4. End-to-end tests

- [x] 4.1 Add e2e test: run `mcp-audit sbom`, parse stdout as JSON, verify `bomFormat: "CycloneDX"` and `specVersion: "1.6"`
- [x] 4.2 Add e2e test: run `mcp-audit sbom --format spdx-tag`, verify output contains `SPDXVersion: SPDX-2.3`
- [x] 4.3 Add e2e test: run `mcp-audit sbom --output /tmp/test-sbom.json`, verify file exists and contains valid CycloneDX JSON
- [ ] 4.4 Add e2e test: run `mcp-audit sbom --with-cves` against test server with known CVE, verify vulnerability appears in SBOM
