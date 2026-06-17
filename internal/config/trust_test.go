package config

import (
	"path/filepath"
	"testing"
)

func TestLoadTrust(t *testing.T) {
	cfg, err := LoadTrust("testdata/trust_valid.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Trusted) != 2 {
		t.Errorf("expected 2 trusted, got %d", len(cfg.Trusted))
	}
	if cfg.Trusted[0] != "prospect" {
		t.Errorf("expected prospect, got %s", cfg.Trusted[0])
	}
	if len(cfg.Blocked) != 1 {
		t.Errorf("expected 1 blocked, got %d", len(cfg.Blocked))
	}
	if cfg.Blocked[0] != "evil-package" {
		t.Errorf("expected evil-package, got %s", cfg.Blocked[0])
	}
}

func TestLoadTrustEmpty(t *testing.T) {
	cfg, err := LoadTrust("testdata/trust_empty.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Trusted) != 0 {
		t.Errorf("expected 0 trusted, got %d", len(cfg.Trusted))
	}
	if len(cfg.Blocked) != 0 {
		t.Errorf("expected 0 blocked, got %d", len(cfg.Blocked))
	}
}

func TestLoadTrustMissing(t *testing.T) {
	_, err := LoadTrust("testdata/does_not_exist.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadTrustMalformed(t *testing.T) {
	_, err := LoadTrust("testdata/trust_malformed.json")
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestDefaultTrustPath(t *testing.T) {
	path := DefaultTrustPath()
	if path == "" {
		t.Fatal("expected non-empty path")
	}
	if filepath.Base(path) != "trust.json" {
		t.Errorf("expected trust.json, got %s", filepath.Base(path))
	}
}

func TestScopeForGlobalOnly(t *testing.T) {
	tc := &TrustConfig{
		TrustScope: TrustScope{Trusted: []string{"global-trusted"}, Blocked: []string{"global-blocked"}},
	}

	scope := tc.ScopeFor("any-server", "any-tool")
	if len(scope.Trusted) != 1 || scope.Trusted[0] != "global-trusted" {
		t.Errorf("expected global-trusted, got %v", scope.Trusted)
	}
	if len(scope.Blocked) != 1 || scope.Blocked[0] != "global-blocked" {
		t.Errorf("expected global-blocked, got %v", scope.Blocked)
	}
}

func TestScopeForToolOverride(t *testing.T) {
	tc := &TrustConfig{
		TrustScope: TrustScope{Trusted: []string{"global-trusted"}},
		Tools: map[string]TrustScope{
			"claude": {Trusted: []string{"claude-trusted"}},
		},
	}

	scope := tc.ScopeFor("any-server", "claude")
	if len(scope.Trusted) != 1 || scope.Trusted[0] != "claude-trusted" {
		t.Errorf("expected claude-trusted, got %v", scope.Trusted)
	}
	if len(scope.Blocked) != 0 {
		t.Errorf("expected 0 blocked, got %d", len(scope.Blocked))
	}

	scope = tc.ScopeFor("any-server", "cursor")
	if len(scope.Trusted) != 1 || scope.Trusted[0] != "global-trusted" {
		t.Errorf("expected global-trusted fallback, got %v", scope.Trusted)
	}
}

func TestScopeForServerOverride(t *testing.T) {
	tc := &TrustConfig{
		TrustScope: TrustScope{Trusted: []string{"global-trusted"}},
		Tools: map[string]TrustScope{
			"claude": {Trusted: []string{"claude-trusted"}},
		},
		Servers: map[string]TrustScope{
			"filesystem": {Blocked: []string{"bad-pkg"}},
		},
	}

	scope := tc.ScopeFor("filesystem", "claude")
	if len(scope.Trusted) != 0 {
		t.Errorf("expected 0 trusted (server override), got %d", len(scope.Trusted))
	}
	if len(scope.Blocked) != 1 || scope.Blocked[0] != "bad-pkg" {
		t.Errorf("expected bad-pkg blocked, got %v", scope.Blocked)
	}

	scope = tc.ScopeFor("other", "claude")
	if len(scope.Trusted) != 1 || scope.Trusted[0] != "claude-trusted" {
		t.Errorf("expected claude-trusted fallback, got %v", scope.Trusted)
	}
}

func TestScopeForUnknown(t *testing.T) {
	tc := &TrustConfig{
		TrustScope: TrustScope{Trusted: []string{"global-trusted"}},
	}

	scope := tc.ScopeFor("unknown", "unknown")
	if len(scope.Trusted) != 1 || scope.Trusted[0] != "global-trusted" {
		t.Errorf("expected global-trusted fallback, got %v", scope.Trusted)
	}
}

func TestLoadScopedConfig(t *testing.T) {
	cfg, err := LoadTrust("testdata/trust_scoped.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	scope := cfg.ScopeFor("filesystem", "claude")
	if len(scope.Blocked) != 1 || scope.Blocked[0] != "filesystem-blocked" {
		t.Errorf("expected filesystem-blocked, got %v", scope.Blocked)
	}

	scope = cfg.ScopeFor("other", "claude")
	if len(scope.Trusted) != 1 || scope.Trusted[0] != "claude-trusted" {
		t.Errorf("expected claude-trusted, got %v", scope.Trusted)
	}

	scope = cfg.ScopeFor("other", "other")
	if len(scope.Trusted) != 1 || scope.Trusted[0] != "global-trusted" {
		t.Errorf("expected global-trusted, got %v", scope.Trusted)
	}
}
