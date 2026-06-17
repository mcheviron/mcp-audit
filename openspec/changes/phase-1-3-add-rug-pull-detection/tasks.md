## 1. Snapshot storage

- [ ] 1.1 Create `internal/snapshot/` package with `Snapshot` struct and JSON serialization
- [ ] 1.2 Implement `SaveSnapshot(serverKey string, tools []mcp.Tool) error` — write to `~/.config/mcp-audit/snapshots/`
- [ ] 1.3 Implement `LoadSnapshot(serverKey string) (*Snapshot, error)` — read and unmarshal
- [ ] 1.4 Create snapshot directory with 0700 permissions on first write
- [ ] 1.5 Generate composite server key from name + url/command

## 2. Tool hashing

- [ ] 2.1 Implement `HashToolDescription(tool mcp.Tool) string` — SHA-256 of normalized description
- [ ] 2.2 Implement `HashToolSchema(tool mcp.Tool) string` — SHA-256 of canonical JSON marshal of InputSchema
- [ ] 2.3 Normalize JSON before hashing (sorted keys, no whitespace) for stable hashes

## 3. Drift comparison

- [ ] 3.1 Implement `CompareSnapshots(old, new *Snapshot) []DriftFinding` — detect adds, removes, changes
- [ ] 3.2 Assign severity: HIGH for schema changes, MEDIUM for additions/description changes, INFO for removals
- [ ] 3.3 Detect schema broadening (new properties added) vs narrowing

## 4. Pinned tool verification

- [ ] 4.1 Add `PinnedTools map[string]string` to `TrustConfig` in `config/trust.go`
- [ ] 4.2 Parse `pinned_tools` from trust config JSON
- [ ] 4.3 Verify pinned hashes against live tools during drift comparison
- [ ] 4.4 Report CRITICAL for pinned hash mismatches, HIGH for missing pinned tools

## 5. Probe pipeline integration

- [ ] 5.1 Load snapshot before `ListTools` call in `runMCPProbes`
- [ ] 5.2 Run drift comparison after `ListTools` succeeds
- [ ] 5.3 Save new snapshot after comparison completes
- [ ] 5.4 Add `--snapshot-dir`, `--no-snapshot`, `--no-trust-on-first-use` CLI flags

## 6. Tests

- [ ] 6.1 Test snapshot save/load round-trip with mock tools
- [ ] 6.2 Test drift detection: add, remove, description change, schema change
- [ ] 6.3 Test pinned hash match and mismatch scenarios
- [ ] 6.4 Test first-scan baseline (no drift reported)
- [ ] 6.5 Test server identity stability across scans
