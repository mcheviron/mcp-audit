package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/mcheviron/mcp-audit/internal/config"
	"github.com/mcheviron/mcp-audit/internal/intel"
)

func TestSetTrustConfigEmbeddedFallback(t *testing.T) {
	s := New(ScannerConfig{})

	err := s.SetTrustConfig("")
	if err != nil {
		t.Fatalf("expected no error with embedded fallback, got %v", err)
	}

	if s.Trust == nil {
		t.Fatal("expected trust config to be set from embedded defaults")
	}

	found := slices.Contains(s.Trust.Trusted, "@anthropic/")
	if !found {
		t.Error("embedded trust config should include @anthropic/")
	}
}

func TestSetTrustConfigEmbeddedFallbackMissingDefault(t *testing.T) {
	t.Setenv("HOME", "/nonexistent-home-dir-xyz")

	s := New(ScannerConfig{})

	err := s.SetTrustConfig("")
	if err != nil {
		t.Fatalf("expected no error when home dir doesn't exist, got %v", err)
	}

	if s.Trust == nil {
		t.Fatal("expected trust config to be set from embedded defaults")
	}

	found := slices.Contains(s.Trust.Trusted, "@anthropic/")
	if !found {
		t.Error("embedded trust config should include @anthropic/")
	}
}

func TestSetTrustConfigUserOverrideEmbedded(t *testing.T) {
	tmpDir := t.TempDir()
	userPath := filepath.Join(tmpDir, "trust.json")

	userConfig := config.TrustConfig{
		TrustScope: config.TrustScope{
			Trusted: []string{"custom-trusted"},
			Blocked: []string{"custom-blocked"},
		},
	}
	data, err := json.Marshal(userConfig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(userPath, data, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	s := New(ScannerConfig{})
	if err := s.SetTrustConfig(userPath); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if s.Trust == nil {
		t.Fatal("expected trust config to be set")
	}
	if len(s.Trust.Trusted) != 1 || s.Trust.Trusted[0] != "custom-trusted" {
		t.Errorf("expected custom-trusted, got %v", s.Trust.Trusted)
	}
	if len(s.Trust.Blocked) != 1 || s.Trust.Blocked[0] != "custom-blocked" {
		t.Errorf("expected custom-blocked, got %v", s.Trust.Blocked)
	}
}

func TestSetTrustConfigExplicitPathNotFound(t *testing.T) {
	s := New(ScannerConfig{})

	err := s.SetTrustConfig("")
	if err != nil {
		t.Fatalf("expected no error with default path fallback, got %v", err)
	}

	if s.Trust == nil {
		t.Fatal("expected trust config from embedded defaults")
	}
}

func TestLoadEmbeddedDefaultsServerScope(t *testing.T) {
	s := New(ScannerConfig{})
	if err := s.loadEmbeddedDefaults(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if s.Trust == nil {
		t.Fatal("expected trust config")
	}
	if s.Trust.Servers == nil {
		t.Fatal("expected Servers map to be initialized")
	}
	if s.Trust.Tools == nil {
		t.Fatal("expected Tools map to be initialized")
	}
	if s.Trust.PinnedTools == nil {
		t.Fatal("expected PinnedTools map to be initialized")
	}
}

func TestLoadEmbeddedDefaultsViaIntel(t *testing.T) {
	tf, err := intel.LoadDefaults()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	s := New(ScannerConfig{})
	if err := s.loadEmbeddedDefaults(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(s.Trust.Trusted) != len(tf.Trusted) {
		t.Errorf("trusted count mismatch: scanner=%d intel=%d",
			len(s.Trust.Trusted), len(tf.Trusted))
	}

	for i, expected := range tf.Trusted {
		if s.Trust.Trusted[i] != expected {
			t.Errorf("trusted[%d]: expected %s, got %s", i, expected, s.Trust.Trusted[i])
		}
	}
}
