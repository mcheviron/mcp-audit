## Why

MCP spec explicitly states tools `MAY change over time` across sessions. A benign server approved today can silently swap its tool definitions tomorrow — adding shell-exec capabilities to a previously read-only tool, or redirecting a URL-fetch tool to exfiltrate data. OWASP MCP Top 10 names rug pulls a Key Risk. ReversingLabs cites 5 independent security experts confirming the attack. MCPoison (CVE-2025-54136) demonstrated this against Cursor IDE. MCPShield and MCP-Scan both implement drift detection. mcp-audit currently fetches tools ephemerally with zero cross-session comparison.

## What Changes

- Persist tool definition snapshots to disk after first scan (`~/.config/mcp-audit/snapshots/<server>.json`)
- On subsequent scans, compare current tool definitions against stored snapshots
- Detect: new tools added, existing tools removed, tool description changed, InputSchema changed
- Cryptographic hash (SHA-256) of each tool definition for tamper-evident comparison
- Report drift at HIGH severity when capabilities expand (new dangerous tools, schema broadened), MEDIUM when definitions change, INFO when tools are removed
- `--snapshot-dir` flag to override snapshot location, `--no-snapshot` to disable persistence

## Capabilities

### New Capabilities

- `tool-drift-detection`: Cross-session tool definition integrity verification via cryptographic hash pinning and snapshot comparison.

## Impact

- `internal/snapshot/` — new package: `store.go` (snapshot read/write), `compare.go` (diff logic), `hash.go` (SHA-256 hashing)
- `internal/scanner/dynamic.go` — load snapshot before ListTools, compare after, save new snapshot
- `main.go` — `--snapshot-dir`, `--no-snapshot` flags
- `internal/config/trust.go` — `TrustConfig` gains `PinnedTools map[string]string` for known-good hashes

## Non-Goals

- Real-time drift detection (daemon mode, separate proposal)
- Centralized hash registry or blockchain verification
- Automatic rollback or blocking — detection only
- Drift detection for transport-level changes (URL changes, command changes) — focus on tool definitions
