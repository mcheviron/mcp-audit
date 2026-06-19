## Context

SARIF drops PASS results, has no CWE/OWASP taxonomy. JSON has no metadata. Table has no grouping. No JUnit output. Exit codes coarse (0/1/2). Production tools need standards-compliant, CI-integrable reports.

## Goals / Non-Goals

**Goals:** SARIF with CWE mappings, OWASP MCP Top 10 refs, PASS inclusion. JUnit XML output. JSON metadata fields. Table grouping by severity. Granular exit codes (0-4).

**Non-Goals:** HTML/PDF reports, interactive TUI, historical comparison.

## Decisions

### CWE taxonomy in SARIF

Add `taxa` section mapping rule IDs to CWE:
- `mcp-audit/dynamic-critical` → CWE-918 (SSRF)
- `mcp-audit/dynamic-high` → CWE-200 (Info Exposure)
- `mcp-audit/static-info` → CWE-350 (Typosquat)
- `mcp-audit/static-critical` → CWE-506 (Malicious Code)

Add `reportingDescriptor` per rule with `helpUri` pointing to OWASP MCP Top 10.

### JUnit: `<testsuite>` with `<testcase>` per finding

Each finding → `<testcase name="server: finding">`. CRITICAL/HIGH → `<failure>`. MEDIUM → `<error>`. LOW/INFO → `<skipped>`. PASS → passed testcase. This maps naturally to CI test result viewers.

### JSON metadata

Add `{"tool": "mcp-audit", "version": "0.1.0", "scan_time": "<RFC3339>", "summary": {"critical": N, ...}}` wrapper.

### Exit codes

0 = clean, 1 = CRITICAL found, 2 = HIGH found, 3 = MEDIUM found, 4 = scan error. LOW/INFO/PASS exit 0.
