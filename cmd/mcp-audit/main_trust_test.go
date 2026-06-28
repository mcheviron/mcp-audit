package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/mcheviron/mcp-audit/internal/intel"
)

func TestLoadEffectiveTrustNilWhenNoHome(t *testing.T) {
	tf := loadEffectiveTrust()
	if tf == nil {
		t.Fatal("expected non-nil trust file even when no local config")
	}
}

func TestMergeTrustFilesAddsNewTrusted(t *testing.T) {
	base := &intel.TrustFile{
		Version: "1.0.0",
		Trusted: []string{"@anthropic/", "@microsoft/"},
		Blocked: []string{"evil-pkg"},
	}

	overlay := &intel.TrustFile{
		Trusted: []string{"@google/", "@vercel/"},
		Blocked: []string{"another-evil"},
	}

	merged := mergeTrustFiles(base, overlay)

	if len(merged.Trusted) != 4 {
		t.Errorf("expected 4 trusted, got %d: %v", len(merged.Trusted), merged.Trusted)
	}
	if len(merged.Blocked) != 2 {
		t.Errorf("expected 2 blocked, got %d: %v", len(merged.Blocked), merged.Blocked)
	}
}

func TestMergeTrustFilesNoOverwrites(t *testing.T) {
	base := &intel.TrustFile{
		Trusted: []string{"@anthropic/"},
	}

	overlay := &intel.TrustFile{
		Trusted: []string{"@anthropic/", "@microsoft/"},
	}

	merged := mergeTrustFiles(base, overlay)

	if len(merged.Trusted) != 2 {
		t.Errorf("expected 2 trusted (no dups), got %d: %v", len(merged.Trusted), merged.Trusted)
	}
}

func TestMergeTrustFilesNilOverlay(t *testing.T) {
	base := &intel.TrustFile{
		Trusted: []string{"@anthropic/"},
	}

	merged := mergeTrustFiles(base, &intel.TrustFile{})

	if len(merged.Trusted) != 1 {
		t.Errorf("expected 1 trusted, got %d", len(merged.Trusted))
	}
}

func TestMergeTrustFilesPreservesServers(t *testing.T) {
	base := &intel.TrustFile{
		Servers: map[string]intel.Scope{
			"filesystem": {Trusted: []string{"fs-trusted"}},
		},
	}

	overlay := &intel.TrustFile{
		Servers: map[string]intel.Scope{
			"postgres": {Trusted: []string{"pg-trusted"}},
		},
	}

	merged := mergeTrustFiles(base, overlay)

	if merged.Servers == nil {
		t.Fatal("expected Servers not nil")
	}
	if len(merged.Servers) != 2 {
		t.Errorf("expected 2 servers, got %d", len(merged.Servers))
	}
}

func TestWriteTrustFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "trust.json")

	tf := &intel.TrustFile{
		Version: "1.0.0",
		Trusted: []string{"test-trusted"},
	}

	writeTrustFile(path, tf)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}

	var readBack intel.TrustFile
	if err := json.Unmarshal(data, &readBack); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if readBack.Version != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", readBack.Version)
	}
	if len(readBack.Trusted) != 1 || readBack.Trusted[0] != "test-trusted" {
		t.Errorf("expected test-trusted, got %v", readBack.Trusted)
	}
}

func TestTrustExportOutputsJSON(t *testing.T) {
	tf := loadEffectiveTrust()

	data, err := json.Marshal(tf)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if !json.Valid(data) {
		t.Fatal("expected valid JSON")
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if _, ok := parsed["trusted"]; !ok {
		t.Error("expected 'trusted' field in export")
	}
}

func TestTrustUpdateMockFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tf := intel.TrustFile{
			Version:     "2.0.0",
			GeneratedAt: "2026-07-01T00:00:00Z",
			Trusted:     []string{"@anthropic/", "@modelcontextprotocol/", "@new-org/"},
		}
		json.NewEncoder(w).Encode(tf)
	}))
	defer srv.Close()

	data, err := fetchURL(srv.URL)
	if err != nil {
		t.Fatalf("fetchURL: %v", err)
	}

	var tf intel.TrustFile
	if err := json.Unmarshal(data, &tf); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if tf.Version != "2.0.0" {
		t.Errorf("expected version 2.0.0, got %s", tf.Version)
	}
	if len(tf.Trusted) != 3 {
		t.Errorf("expected 3 trusted, got %d", len(tf.Trusted))
	}
}

func TestTrustImportMerge(t *testing.T) {
	base := &intel.TrustFile{
		Version: "1.0.0",
		Trusted: []string{"@anthropic/"},
	}

	imported := &intel.TrustFile{
		Version: "1.1.0",
		Trusted: []string{"@microsoft/", "@google/"},
		Blocked: []string{"bad-pkg"},
	}

	merged := mergeTrustFiles(base, imported)

	if len(merged.Trusted) != 3 {
		t.Errorf("expected 3 trusted, got %d: %v", len(merged.Trusted), merged.Trusted)
	}
	if len(merged.Blocked) != 1 || merged.Blocked[0] != "bad-pkg" {
		t.Errorf("expected blocked to contain bad-pkg, got %v", merged.Blocked)
	}
}

func TestVerifyChecksumMatch(t *testing.T) {
	data := []byte(`{"version":"1.0.0","trusted":["@anthropic/"]}`)
	hash := sha256Hex(data)
	checksumFile := []byte(hash + "  trust.json\n")

	if err := verifyChecksum(data, checksumFile); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestVerifyChecksumMismatch(t *testing.T) {
	data := []byte(`{"version":"1.0.0","trusted":["@anthropic/"]}`)
	checksumFile := []byte("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef  trust.json\n")

	if err := verifyChecksum(data, checksumFile); err == nil {
		t.Fatal("expected error for checksum mismatch")
	}
}

func TestVerifyChecksumEmptyFile(t *testing.T) {
	data := []byte(`{"version":"1.0.0"}`)
	checksumFile := []byte("")

	if err := verifyChecksum(data, checksumFile); err != nil {
		t.Fatalf("expected no error for empty checksum file, got: %v", err)
	}
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
