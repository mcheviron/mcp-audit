## 1. Snapshot storage

- [x] 1.1 Create `internal/snapshot/` package with `Snapshot` struct and JSON serialization
- [x] 1.2 Implement `SaveSnapshot(serverKey string, tools []mcp.Tool) error` — write to `~/.config/mcp-audit/snapshots/`
- [x] 1.3 Implement `LoadSnapshot(serverKey string) (*Snapshot, error)` — read and unmarshal
- [x] 1.4 Create snapshot directory with 0700 permissions on first write
- [x] 1.5 Generate composite server key from name + url/command

## 2. Tool hashing

- [x] 2.1 Implement `HashToolDescription(tool mcp.Tool) string` — SHA-256 of normalized description
- [x] 2.2 Implement `HashToolSchema(tool mcp.Tool) string` — SHA-256 of canonical JSON marshal of InputSchema
- [x] 2.3 Normalize JSON before hashing (sorted keys, no whitespace) for stable hashes

## 3. Drift comparison

- [x] 3.1 Implement `CompareSnapshots(old, new *Snapshot) []DriftFinding` — detect adds, removes, changes
- [x] 3.2 Assign severity: HIGH for schema changes, MEDIUM for additions/description changes, INFO for removals
- [x] 3.3 Detect schema broadening (new properties added) vs narrowing

## 4. Pinned tool verification

- [x] 4.1 Add `PinnedTools map[string]string` to `TrustConfig` in `config/trust.go`
- [x] 4.2 Parse `pinned_tools` from trust config JSON
- [x] 4.3 Verify pinned hashes against live tools during drift comparison
- [x] 4.4 Report CRITICAL for pinned hash mismatches, HIGH for missing pinned tools

## 5. Probe pipeline integration

- [x] 5.1 Load snapshot before `ListTools` call in `runMCPProbes`
- [x] 5.2 Run drift comparison after `ListTools` succeeds
- [x] 5.3 Save new snapshot after comparison completes
- [x] 5.4 Add `--snapshot-dir`, `--no-snapshot`, `--no-trust-on-first-use` CLI flags

## 6. Tests

- [x] 6.1 Test snapshot save/load round-trip with mock tools
- [x] 6.2 Test drift detection: add, remove, description change, schema change
- [x] 6.3 Test pinned hash match and mismatch scenarios
- [x] 6.4 Test first-scan baseline (no drift reported)
- [x] 6.5 Test server identity stability across scans
