## Context

mcp-audit already discovers MCP server configurations and queries CVE databases. SBOM generation is a serialization concern: take the inventory data and format it as CycloneDX or SPDX. No new network probes or analysis — pure formatting of existing discovery data.

cyclonedx-go and spdx/tools-go are the standard Go libraries for SBOM generation. Both are external dependencies, which violates stdlib-first constraint. Manual struct definitions for the minimal subset of each spec needed for MCP server inventory avoids the dependency.

## Goals / Non-Goals

**Goals:**
- CycloneDX 1.6 JSON, CycloneDX 1.6 XML output
- SPDX 2.3 JSON, SPDX 2.3 tag-value output
- Optional CVE inclusion via `--with-cves`
- `--output` flag for file output
- Zero external dependencies
- Reuse existing `config.Discover()` for inventory

**Non-Goals:**
- Recursive dependency resolution
- SBOM signing
- SPDX 3.0
- CycloneDX XML via `encoding/xml` (stdlib) — JSON is primary; XML as secondary

## Decisions

### Decision 1: Manual struct definitions for minimal spec subset

Define Go structs for CycloneDX 1.6 Bom, Component, Vulnerability, and Tool with JSON and XML tags. Similarly for SPDX 2.3 Document, Package, and CreationInfo. Only include fields needed for MCP server inventory — not full spec coverage.

**Alternative:** Use cyclonedx-go library. Rejected — external dependency. Manual structs are ~200 lines max per format.

**Fields included (CycloneDX):** bomFormat, specVersion, serialNumber, version, metadata.tools, metadata.component, components[].name/version/type/purl/description/supplier, vulnerabilities[].id/source/ratings/affects.

**Fields included (SPDX):** SPDXID, spdxVersion, dataLicense, name, creationInfo, packages[].name/versionInfo/supplier/externalRefs.

### Decision 2: CycloneDX XML via encoding/xml

Go's `encoding/xml` supports CycloneDX schema via struct tags. JSON is default (`.json` struct tags + `encoding/json`), XML uses `.xml` struct tags + `encoding/xml`. Separate marshal functions per format.

### Decision 3: CVE inclusion is blocking I/O

`--with-cves` triggers the existing CVE scanning pipeline (`internal/scanner/cve.go`) against discovered packages. This means network calls to NVD and GitHub Advisory APIs. Without the flag, SBOM generation is pure static — no network.

## Risks / Trade-offs

- [Risk] Minimal spec subset may miss fields some SBOM consumers require → Mitigation: document exact fields included; consumers needing full spec should use dedicated SBOM tools
- [Risk] CycloneDX XML namespace handling is error-prone with encoding/xml → Mitigation: comprehensive round-trip validation tests (marshal → unmarshal → compare)
- [Risk] CVE scanning during SBOM generation adds latency (~2-5s per package) → Mitigation: `--with-cves` is opt-in; without it, SBOM generation is instant
