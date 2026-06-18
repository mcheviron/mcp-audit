package configfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMissingFile(t *testing.T) {
	cfg := LoadPath("/nonexistent/path/config.json")
	if cfg == nil {
		t.Fatal("LoadPath should never return nil")
	}
	if cfg.Format != "" || cfg.Timeout != 0 {
		t.Error("missing config should have zero values")
	}
}

func TestLoadValidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	content := `{"format": "json", "timeout": 15, "no_color": true}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := LoadPath(path)
	if cfg.Format != "json" {
		t.Errorf("expected format=json, got %q", cfg.Format)
	}
	if cfg.Timeout != 15 {
		t.Errorf("expected timeout=15, got %d", cfg.Timeout)
	}
	if !cfg.NoColor {
		t.Error("expected no_color=true")
	}
}

func TestLoadInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("{invalid"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := LoadPath(path)
	if cfg == nil {
		t.Fatal("invalid JSON should return empty config, not nil")
	}
	if cfg.Format != "" {
		t.Error("invalid JSON should have zero values")
	}
}

func TestLoadAllConfigKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	content := `{
		"format": "sarif",
		"trust_config": "/tmp/trust.json",
		"targets": "http://1.2.3.4/",
		"allow_hosts": "example.com",
		"block_hosts": "169.254.169.254",
		"timeout": 60,
		"concurrency": 5,
		"probe_depth": "full",
		"max_response": 1024,
		"no_color": true,
		"snapshot_dir": "/tmp/snaps"
	}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := LoadPath(path)
	if cfg.Format != "sarif" {
		t.Errorf("format: got %q", cfg.Format)
	}
	if cfg.Timeout != 60 {
		t.Errorf("timeout: got %d", cfg.Timeout)
	}
	if cfg.Concurrency != 5 {
		t.Errorf("concurrency: got %d", cfg.Concurrency)
	}
	if cfg.ProbeDepth != "full" {
		t.Errorf("probe_depth: got %q", cfg.ProbeDepth)
	}
}
