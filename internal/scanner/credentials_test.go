package scanner

import (
	"strings"
	"testing"

	"github.com/mcheviron/mcp-audit/internal/config"
)

func credConfig() config.Config {
	raw := []byte(`{"mcpServers":{"leaky":{"command":"npx","args":["-y","pkg"],"env":{"API_KEY":"sk-` +
		strings.Repeat("a", 20) + `"}}}}`)
	return config.Config{
		Tool: "claude",
		Path: "/tmp/config.json",
		Raw:  raw,
		Servers: []config.ServerEntry{{
			Name:       "leaky",
			Tool:       "claude",
			Transport:  "stdio",
			Command:    "npx",
			Args:       []string{"-y", "pkg"},
			ConfigPath: "/tmp/config.json",
			Env:        map[string]string{"API_KEY": "sk-" + strings.Repeat("a", 20)},
		}},
	}
}

func TestCheckCredentialsReportsCritical(t *testing.T) {
	s := &Scanner{TestConfigs: []config.Config{credConfig()}}
	results := s.checkCredentials(credConfig())
	if len(results) == 0 {
		t.Fatal("expected credential findings")
	}
	for _, r := range results {
		if r.Severity != SevCritical {
			t.Errorf("expected CRITICAL, got %v: %s", r.Severity, r.Finding)
		}
	}
}

func TestCheckCredentialsNoSecretScanSuppresses(t *testing.T) {
	s := &Scanner{ScannerConfig: ScannerConfig{Snapshot: SnapshotConfig{NoSecretScan: true}}}
	results := s.checkCredentials(credConfig())
	if len(results) != 0 {
		t.Fatalf("expected no findings when NoSecretScan, got %v", results)
	}
}

func TestCheckCredentialsRedactsRawValue(t *testing.T) {
	secret := "sk-" + strings.Repeat("a", 20)
	s := &Scanner{TestConfigs: []config.Config{credConfig()}}
	results := s.checkCredentials(credConfig())
	for _, r := range results {
		if strings.Contains(r.Finding, secret) {
			t.Fatalf("raw secret leaked into finding: %q", r.Finding)
		}
		if strings.Contains(r.Detail, secret) {
			t.Fatalf("raw secret leaked into detail: %q", r.Detail)
		}
	}
}

func TestCheckCredentialsCleanConfig(t *testing.T) {
	raw := []byte(`{"mcpServers":{"safe":{"command":"npx","args":["-y","pkg"]}}}`)
	cfg := config.Config{
		Tool: "claude",
		Path: "/tmp/config.json",
		Raw:  raw,
		Servers: []config.ServerEntry{{
			Name:       "safe",
			Tool:       "claude",
			Transport:  "stdio",
			Command:    "npx",
			Args:       []string{"-y", "pkg"},
			ConfigPath: "/tmp/config.json",
		}},
	}
	s := &Scanner{TestConfigs: []config.Config{cfg}}
	if results := s.checkCredentials(cfg); len(results) != 0 {
		t.Fatalf("expected no findings for clean config, got %v", results)
	}
}

func TestStaticIntegratesCredentialScan(t *testing.T) {
	s := &Scanner{TestConfigs: []config.Config{credConfig()}}
	out, err := s.Static()
	if err != nil {
		t.Fatalf("static: %v", err)
	}
	var found bool
	for _, r := range out.Results {
		if r.Severity == SevCritical && strings.Contains(r.Finding, "OpenAI API key") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected CRITICAL OpenAI finding in static results")
	}
}
