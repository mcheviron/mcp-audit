## Context

MCP spec states tools `MAY change over time` — definitions are stable only within a single connection. Cross-session, a server can add, remove, or modify tools arbitrarily. This is a documented attack vector: an initially benign server is approved, then silently updated to include malicious tools or broaden existing tool capabilities.

Current code: `dynamic.go:180` calls `ListTools`, line 194 calls `probeMCPTool` — tools used ephemerally with zero cross-session state. No persistence, no comparison, no drift detection.

## Goals / Non-Goals

**Goals:**
- Persist tool definition snapshots after first successful scan
- Compare current tool definitions against stored snapshots on subsequent scans
- Detect additions, removals, description changes, and schema changes
- SHA-256 hash per tool for tamper-evident integrity
- Report drift by severity: HIGH for capability expansion, MEDIUM for definition changes, INFO for removals
- Trust config integration: `PinnedTools` map with known-good hashes for pre-approved definitions

**Non-Goals:**
- Real-time monitoring (daemon mode, separate proposal)
- Centralized hash registry or blockchain verification
- Automatic blocking — detection only at this stage

## Decisions

### Snapshot format: JSON-per-server, stored in XDG data dir

`~/.config/mcp-audit/snapshots/<server-name>.json` containing:
```json
{
  "server": "filesystem",
  "url": "http://localhost:8080",
  "scanned_at": "2026-06-17T10:00:00Z",
  "tools": [
    {"name": "read_file", "description_hash": "sha256:abc123", "schema_hash": "sha256:def456"}
  ]
}
```

Alternative: single combined file. Rejected — per-server files are atomic, easier to diff, and avoid write conflicts.

### Hash scope: description + schema separately

Two hashes per tool allow distinguishing "description changed" (possible injection) from "schema changed" (behavioral change). Schema changes are more severe.

### Trust config integration: PinnedTools map

`TrustConfig.PinnedTools` maps `"<server>/<tool>"` to expected SHA-256 hash. If pinned hash doesn't match, CRITICAL finding. This allows users to lock known-good tools after manual review.

### Drift severity logic

- Tool added since last scan → MEDIUM (new attack surface)
- Tool removed → INFO (could be benign cleanup)
- Description changed, schema same → MEDIUM (possible injection)
- Schema changed → HIGH (behavioral change)
- Schema broadened (new params added) → HIGH
- Schema narrowed → INFO
- Pinned hash mismatch → CRITICAL
- No drift → PASS

## Risks / Trade-offs

- **First-scan trust** → First snapshot is trusted by default. Mitigation: `--trust-on-first-use` flag (default true). Users can set `--no-trust-on-first-use` to require pre-populated pinned hashes.
- **Snapshot tampering** → Attacker with filesystem access could modify snapshots. Mitigation: this is an audit tool, not an intrusion detection system. Filesystem access implies broader compromise.
- **Server identity** → Servers identified by name, which can collide. Mitigation: use `name + url/command` composite key for snapshot lookup.

## Open Questions

- Should version bumps (server version change without tool change) be flagged?
- How to handle servers that generate dynamic tool lists (e.g., based on available plugins)?
