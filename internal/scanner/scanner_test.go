package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/mostafaelataby-cheviron/mcp-audit/internal/config"
	"github.com/mostafaelataby-cheviron/mcp-audit/internal/intel"
)

func TestSetTrustConfigEmbeddedFallback(t *testing.T) {
	s := New()

	err := s.SetTrustConfig("")
	if err != nil {
		t.Fatalf("expected no error with embedded fallback, got %v", err)
	}

	if s.TrustConfig == nil {
		t.Fatal("expected trust config to be set from embedded defaults")
	}

	found := slices.Contains(s.TrustConfig.Trusted, "@anthropic/")
	if !found {
		t.Error("embedded trust config should include @anthropic/")
	}
}

func TestSetTrustConfigEmbeddedFallbackMissingDefault(t *testing.T) {
	t.Setenv("HOME", "/nonexistent-home-dir-xyz")

	s := New()

	err := s.SetTrustConfig("")
	if err != nil {
		t.Fatalf("expected no error when home dir doesn't exist, got %v", err)
	}

	if s.TrustConfig == nil {
		t.Fatal("expected trust config to be set from embedded defaults")
	}

	found := slices.Contains(s.TrustConfig.Trusted, "@anthropic/")
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

	s := New()
	if err := s.SetTrustConfig(userPath); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if s.TrustConfig == nil {
		t.Fatal("expected trust config to be set")
	}
	if len(s.TrustConfig.Trusted) != 1 || s.TrustConfig.Trusted[0] != "custom-trusted" {
		t.Errorf("expected custom-trusted, got %v", s.TrustConfig.Trusted)
	}
	if len(s.TrustConfig.Blocked) != 1 || s.TrustConfig.Blocked[0] != "custom-blocked" {
		t.Errorf("expected custom-blocked, got %v", s.TrustConfig.Blocked)
	}
}

func TestSetTrustConfigExplicitPathNotFound(t *testing.T) {
	s := New()

	err := s.SetTrustConfig("")
	if err != nil {
		t.Fatalf("expected no error with default path fallback, got %v", err)
	}

	if s.TrustConfig == nil {
		t.Fatal("expected trust config from embedded defaults")
	}
}

func TestLoadEmbeddedDefaultsServerScope(t *testing.T) {
	s := New()
	if err := s.loadEmbeddedDefaults(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if s.TrustConfig == nil {
		t.Fatal("expected trust config")
	}
	if s.TrustConfig.Servers == nil {
		t.Fatal("expected Servers map to be initialized")
	}
	if s.TrustConfig.Tools == nil {
		t.Fatal("expected Tools map to be initialized")
	}
	if s.TrustConfig.PinnedTools == nil {
		t.Fatal("expected PinnedTools map to be initialized")
	}
}

func TestLoadEmbeddedDefaultsViaIntel(t *testing.T) {
	tf, err := intel.LoadDefaults()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	s := New()
	if err := s.loadEmbeddedDefaults(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(s.TrustConfig.Trusted) != len(tf.Trusted) {
		t.Errorf("trusted count mismatch: scanner=%d intel=%d",
			len(s.TrustConfig.Trusted), len(tf.Trusted))
	}

	for i, expected := range tf.Trusted {
		if s.TrustConfig.Trusted[i] != expected {
			t.Errorf("trusted[%d]: expected %s, got %s", i, expected, s.TrustConfig.Trusted[i])
		}
	}
}
