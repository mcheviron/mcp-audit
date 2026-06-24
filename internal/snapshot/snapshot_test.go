package snapshot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func toolEntry(name, descHash, schemaHash string, props ...string) ToolEntry {
	return ToolEntry{Name: name, DescriptionHash: descHash, SchemaHash: schemaHash, Properties: props}
}

func TestMakeKey(t *testing.T) {
	k1 := MakeKey("filesystem", "http://localhost:8080", "")
	k2 := MakeKey("filesystem", "http://localhost:8080", "")
	if k1 != k2 {
		t.Fatalf("same inputs should produce same key: %q vs %q", k1, k2)
	}

	k3 := MakeKey("filesystem", "http://localhost:9090", "")
	if k1 == k3 {
		t.Error("different URLs should produce different keys")
	}

	k4 := MakeKey("", "", "node server.js")
	if k4 == "unknown" || k4 == "" {
		t.Errorf("command-only key should not be empty: %q", k4)
	}
}

func TestMakeKeyNoCollision(t *testing.T) {
	k1 := MakeKey("filesystem", "https://example.com/write", "")
	k2 := MakeKey("filesystem", "https://example.com", "write")
	if k1 == k2 {
		t.Fatalf("URL path vs command should not collide: %q", k1)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()

	tools := []ToolEntry{
		toolEntry("read_file", "sha256:abc123", "sha256:def456", "path", "encoding"),
		toolEntry("write_file", "sha256:111aaa", "sha256:222bbb", "path", "content"),
	}

	key := MakeKey("test-server", "http://localhost:8080", "")
	err := SaveSnapshot(dir, key, "test-server", "http://localhost:8080", "", tools)
	if err != nil {
		t.Fatalf("SaveSnapshot failed: %v", err)
	}

	snap, err := LoadSnapshot(dir, key)
	if err != nil {
		t.Fatalf("LoadSnapshot failed: %v", err)
	}

	if snap.Server != "test-server" {
		t.Errorf("expected server 'test-server', got %q", snap.Server)
	}
	if len(snap.Tools) != 2 {
		t.Errorf("expected 2 tools, got %d", len(snap.Tools))
	}
	if snap.Tools[0].Name != "read_file" {
		t.Errorf("expected first tool 'read_file', got %q", snap.Tools[0].Name)
	}
	if snap.Tools[1].Name != "write_file" {
		t.Errorf("expected second tool 'write_file', got %q", snap.Tools[1].Name)
	}

	_, err = LoadSnapshot(dir, "nonexistent")
	if err == nil {
		t.Error("LoadSnapshot should fail for nonexistent key")
	}
}

func TestSaveSnapshotCreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "new-subdir", "snapshots")

	tools := []ToolEntry{toolEntry("test_tool", "sha256:xyz", "sha256:abc")}
	key := MakeKey("test", "http://localhost", "")
	err := SaveSnapshot(dir, key, "test", "http://localhost", "", tools)
	if err != nil {
		t.Fatalf("SaveSnapshot failed: %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("not a directory")
	}
	if info.Mode().Perm() != 0700 {
		t.Errorf("expected 0700 permissions, got %o", info.Mode().Perm())
	}
}

func TestHashToolDescription(t *testing.T) {
	h1 := HashToolDescription("Read a file from the filesystem")
	h2 := HashToolDescription("Read a file from the filesystem")
	if h1 != h2 {
		t.Error("same description should produce same hash")
	}

	h3 := HashToolDescription("Write a file to the filesystem")
	if h1 == h3 {
		t.Error("different descriptions should produce different hashes")
	}
}

func TestHashToolSchema(t *testing.T) {
	schema1 := map[string]any{
		"properties": map[string]any{
			"path": map[string]any{"type": "string"},
			"mode": map[string]any{"type": "string"},
		},
	}
	schema2 := map[string]any{
		"properties": map[string]any{
			"mode": map[string]any{"type": "string"},
			"path": map[string]any{"type": "string"},
		},
	}

	h1 := HashToolSchema(schema1)
	h2 := HashToolSchema(schema2)
	if h1 != h2 {
		t.Error("key order should not affect hash")
	}
}

func TestNormalizeJSONStable(t *testing.T) {
	a := map[string]any{"b": 1, "a": 2}
	b := map[string]any{"a": 2, "b": 1}
	na := string(normalizeJSON(a))
	nb := string(normalizeJSON(b))
	if na != nb {
		t.Fatalf("normalized JSON should be equal regardless of key order:\n%s\n%s", na, nb)
	}
}

func TestNormalizeJSONFloat(t *testing.T) {
	schema := map[string]any{"properties": map[string]any{"n": map[string]any{"type": "number", "multipleOf": 1e-10}}}
	h1 := HashToolSchema(schema)
	h2 := HashToolSchema(schema)
	if h1 != h2 {
		t.Error("float values should produce stable hashes")
	}
}

func TestCompareSnapshotsNoDrift(t *testing.T) {
	ts := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	old := &Snapshot{
		Server:    "test",
		ScannedAt: ts,
		Tools:     []ToolEntry{toolEntry("t1", "sha256:a", "sha256:b", "p1")},
	}
	cur := &Snapshot{
		Server: "test",
		Tools:  []ToolEntry{toolEntry("t1", "sha256:a", "sha256:b", "p1")},
	}

	findings := CompareSnapshots(old, cur, nil, true)
	if len(findings) != 1 || findings[0].Severity != SevPass {
		t.Fatalf("expected 1 PASS finding, got %d findings: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Finding, "2026-06-01") {
		t.Fatalf("expected timestamp in finding, got %q", findings[0].Finding)
	}
}

func TestCompareSnapshotsNoDriftZeroTime(t *testing.T) {
	old := &Snapshot{
		Server: "test",
		Tools:  []ToolEntry{toolEntry("t1", "sha256:a", "sha256:b")},
	}
	cur := &Snapshot{
		Server: "test",
		Tools:  []ToolEntry{toolEntry("t1", "sha256:a", "sha256:b")},
	}

	findings := CompareSnapshots(old, cur, nil, true)
	if len(findings) != 1 || findings[0].Severity != SevPass {
		t.Fatalf("expected 1 PASS finding, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Finding, "(unknown)") {
		t.Fatalf("expected '(unknown)' for zero time, got %q", findings[0].Finding)
	}
}

func TestCompareSnapshotsFirstScan(t *testing.T) {
	cur := &Snapshot{
		Server: "test",
		Tools:  []ToolEntry{toolEntry("t1", "sha256:a", "sha256:b")},
	}

	findings := CompareSnapshots(nil, cur, nil, true)
	if len(findings) != 1 || findings[0].Severity != SevPass {
		t.Fatalf("expected 1 PASS (baseline), got %d findings", len(findings))
	}
	if findings[0].DriftType != DriftFirstScan {
		t.Fatalf("expected DriftFirstScan type, got %d", findings[0].DriftType)
	}

	findingsNoTrust := CompareSnapshots(nil, cur, nil, false)
	if len(findingsNoTrust) != 0 {
		t.Fatalf("expected 0 findings with no-trust-on-first-use, got %d", len(findingsNoTrust))
	}
}

func TestCompareSnapshotsToolAdded(t *testing.T) {
	old := &Snapshot{
		Server: "test",
		Tools:  []ToolEntry{toolEntry("t1", "sha256:a", "sha256:b")},
	}
	cur := &Snapshot{
		Server: "test",
		Tools: []ToolEntry{
			toolEntry("t1", "sha256:a", "sha256:b"),
			toolEntry("t2", "sha256:c", "sha256:d"),
		},
	}

	findings := CompareSnapshots(old, cur, nil, true)
	if len(findings) != 1 || findings[0].Severity != SevMedium {
		t.Fatalf("expected 1 MEDIUM (tool added), got %v", findings)
	}
	if !strings.Contains(findings[0].Finding, "t2") {
		t.Fatalf("expected finding about t2, got %q", findings[0].Finding)
	}
}

func TestCompareSnapshotsToolRemoved(t *testing.T) {
	old := &Snapshot{
		Server: "test",
		Tools: []ToolEntry{
			toolEntry("t1", "sha256:a", "sha256:b"),
			toolEntry("t2", "sha256:c", "sha256:d"),
		},
	}
	cur := &Snapshot{
		Server: "test",
		Tools:  []ToolEntry{toolEntry("t1", "sha256:a", "sha256:b")},
	}

	findings := CompareSnapshots(old, cur, nil, true)
	if len(findings) != 1 || findings[0].Severity != SevInfo {
		t.Fatalf("expected 1 INFO (tool removed), got %v", findings)
	}
	if !strings.Contains(findings[0].Finding, "t2") {
		t.Fatalf("expected finding about t2, got %q", findings[0].Finding)
	}
}

func TestCompareSnapshotsDescriptionChanged(t *testing.T) {
	old := &Snapshot{
		Server: "test",
		Tools:  []ToolEntry{toolEntry("t1", "sha256:old_desc", "sha256:schema")},
	}
	cur := &Snapshot{
		Server: "test",
		Tools:  []ToolEntry{toolEntry("t1", "sha256:new_desc", "sha256:schema")},
	}

	findings := CompareSnapshots(old, cur, nil, true)
	if len(findings) != 1 || findings[0].Severity != SevMedium {
		t.Fatalf("expected 1 MEDIUM (desc changed), got %v", findings)
	}
}

func TestCompareSnapshotsDescriptionAndSchemaBothChanged(t *testing.T) {
	old := &Snapshot{
		Server: "test",
		Tools:  []ToolEntry{toolEntry("t1", "sha256:old_desc", "sha256:old_schema")},
	}
	cur := &Snapshot{
		Server: "test",
		Tools:  []ToolEntry{toolEntry("t1", "sha256:new_desc", "sha256:new_schema")},
	}

	findings := CompareSnapshots(old, cur, nil, true)
	if len(findings) < 2 {
		t.Fatalf("expected 2 findings (desc + schema), got %d: %v", len(findings), findings)
	}
	hasDesc := false
	hasSchema := false
	for _, f := range findings {
		if f.DriftType == DriftDescriptionChanged {
			hasDesc = true
		}
		if f.DriftType == DriftSchemaChanged {
			hasSchema = true
		}
	}
	if !hasDesc {
		t.Error("description change finding missing when schema also changed")
	}
	if !hasSchema {
		t.Error("schema change finding missing")
	}
}

func TestCompareSnapshotsSchemaChanged(t *testing.T) {
	old := &Snapshot{
		Server: "test",
		Tools:  []ToolEntry{toolEntry("t1", "sha256:desc", "sha256:old_schema", "p1")},
	}
	cur := &Snapshot{
		Server: "test",
		Tools:  []ToolEntry{toolEntry("t1", "sha256:desc", "sha256:new_schema", "p1")},
	}

	findings := CompareSnapshots(old, cur, nil, true)
	if len(findings) != 1 || findings[0].Severity != SevHigh {
		t.Fatalf("expected 1 HIGH (schema changed), got %v", findings)
	}
}

func TestCompareSnapshotsSchemaBroadened(t *testing.T) {
	old := &Snapshot{
		Server: "test",
		Tools:  []ToolEntry{toolEntry("t1", "sha256:desc", "sha256:old", "path")},
	}
	cur := &Snapshot{
		Server: "test",
		Tools:  []ToolEntry{toolEntry("t1", "sha256:desc", "sha256:new", "command", "path")},
	}

	findings := CompareSnapshots(old, cur, nil, true)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Finding, "broadened") {
		t.Fatalf("expected broadening detection, got %q", findings[0].Finding)
	}
	if findings[0].Severity != SevHigh {
		t.Fatalf("expected HIGH for broadened schema, got %s", findings[0].Severity)
	}
}

func TestCompareSnapshotsSchemaBroadenedFromNil(t *testing.T) {
	old := &Snapshot{
		Server: "test",
		Tools:  []ToolEntry{toolEntry("t1", "sha256:desc", "sha256:old")},
	}
	cur := &Snapshot{
		Server: "test",
		Tools:  []ToolEntry{toolEntry("t1", "sha256:desc", "sha256:new", "path")},
	}

	findings := CompareSnapshots(old, cur, nil, true)
	if len(findings) != 1 || findings[0].Severity != SevHigh {
		t.Fatalf("expected 1 HIGH finding when broadening from nil properties, got %v", findings)
	}
}

func TestCompareSnapshotsSchemaNarrowed(t *testing.T) {
	old := &Snapshot{
		Server: "test",
		Tools:  []ToolEntry{toolEntry("t1", "sha256:desc", "sha256:old", "command", "path")},
	}
	cur := &Snapshot{
		Server: "test",
		Tools:  []ToolEntry{toolEntry("t1", "sha256:desc", "sha256:new", "path")},
	}

	findings := CompareSnapshots(old, cur, nil, true)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Finding, "narrowed") {
		t.Fatalf("expected narrowing detection, got %q", findings[0].Finding)
	}
	if findings[0].Severity != SevInfo {
		t.Fatalf("expected INFO for narrowed schema, got %s", findings[0].Severity)
	}
}

func TestPinnedHashMatch(t *testing.T) {
	old := &Snapshot{
		Server: "test",
		Tools:  []ToolEntry{toolEntry("read_file", "sha256:abc", "sha256:schema")},
	}
	cur := &Snapshot{
		Server: "test",
		Tools:  []ToolEntry{toolEntry("read_file", "sha256:abc", "sha256:schema")},
	}

	pinned := map[string]string{"read_file": "sha256:abc"}
	findings := CompareSnapshots(old, cur, pinned, true)

	for _, f := range findings {
		if f.DriftType == DriftPinnedMismatch || f.DriftType == DriftPinnedMissing {
			t.Fatalf("pinned hash match should not raise finding, got %v", f)
		}
	}
}

func TestPinnedHashMismatch(t *testing.T) {
	old := &Snapshot{
		Server: "test",
		Tools:  []ToolEntry{toolEntry("read_file", "sha256:abc", "sha256:schema")},
	}
	cur := &Snapshot{
		Server: "test",
		Tools:  []ToolEntry{toolEntry("read_file", "sha256:xyz", "sha256:schema")},
	}

	pinned := map[string]string{"read_file": "sha256:abc"}
	findings := CompareSnapshots(old, cur, pinned, true)

	found := false
	for _, f := range findings {
		if f.DriftType == DriftPinnedMismatch && f.Severity == SevCritical {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected CRITICAL pinned mismatch, got %v", findings)
	}
}

func TestPinnedToolMissing(t *testing.T) {
	cur := &Snapshot{
		Server: "test",
		Tools:  []ToolEntry{toolEntry("other_tool", "sha256:abc", "sha256:schema")},
	}

	pinned := map[string]string{"read_file": "sha256:abc"}
	findings := CompareSnapshots(nil, cur, pinned, true)

	found := false
	for _, f := range findings {
		if f.DriftType == DriftPinnedMissing && f.Severity == SevHigh {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected HIGH pinned missing, got %v", findings)
	}
}

func TestServerIdentityStability(t *testing.T) {
	k1 := MakeKey("my-server", "https://example.com/mcp", "")
	k2 := MakeKey("my-server", "https://example.com/mcp", "")
	if k1 != k2 {
		t.Fatalf("same inputs produce different keys: %q vs %q", k1, k2)
	}

	dir := t.TempDir()
	key := MakeKey("my-server", "https://example.com/mcp", "")
	err := SaveSnapshot(dir, key, "my-server", "https://example.com/mcp", "", nil)
	if err != nil {
		t.Fatalf("SaveSnapshot failed: %v", err)
	}
	err = SaveSnapshot(dir, key, "my-server", "https://example.com/mcp", "", nil)
	if err != nil {
		t.Fatalf("second SaveSnapshot should succeed (same key): %v", err)
	}

	key2 := MakeKey("my-server", "https://different.example.com/mcp", "")
	err = SaveSnapshot(dir, key2, "my-server", "https://different.example.com/mcp", "", nil)
	if err != nil {
		t.Fatalf("different URL SaveSnapshot failed: %v", err)
	}

	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(files) != 2 {
		t.Fatalf("expected 2 snapshot files, got %d: %v", len(files), files)
	}
}
