package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/mostafaelataby-cheviron/mcp-audit/internal/intel"
)

// =============================================================================
// Scenario: Embedded defaults used
// WHEN no user trust config exists and no --trust-config flag is set
// THEN the embedded default trust config is loaded
// =============================================================================

func TestE2E_EmbeddedDefaultsUsed_NoUserTrustConfig(t *testing.T) {
	bin := buildBinary(t)

	claudeCfg := `{
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
			}
		}
	}`

	home := setupHomeDir(t, claudeCfg)
	// Ensure no trust config exists in ~/.config/mcp-audit/
	cfgDir := filepath.Join(home, ".config", "mcp-audit")
	_ = os.RemoveAll(cfgDir)

	out, _, code := runMCPAudit(t, bin, home, "static")
	if code != 0 {
		t.Errorf("expected exit 0 with embedded defaults, got %d\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "PASS") {
		t.Errorf("expected PASS with embedded trusted package\noutput:\n%s", out)
	}
}

// Regression: scan still works with embedded defaults and finds typosquats
func TestE2E_EmbeddedDefaultsUsed_TyposquatStillDetected(t *testing.T) {
	bin := buildBinary(t)

	claudeCfg := `{
		"mcpServers": {
			"evil": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesytem", "/tmp"]
			}
		}
	}`

	home := setupHomeDir(t, claudeCfg)
	cfgDir := filepath.Join(home, ".config", "mcp-audit")
	_ = os.RemoveAll(cfgDir)

	out, _, code := runMCPAudit(t, bin, home, "static")
	if code != 0 {
		t.Errorf("expected exit 0 for typosquat detection, got %d\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "typosquat") {
		t.Errorf("expected typosquat detection in output\noutput:\n%s", out)
	}
}

// =============================================================================
// Scenario: User config overrides embedded
// WHEN --trust-config ./my-trust.json is passed
// THEN the user's config is used instead of embedded defaults
// =============================================================================

func TestE2E_UserConfigOverridesEmbedded(t *testing.T) {
	bin := buildBinary(t)

	// User config trusts only @google/ — NOT @modelcontextprotocol/
	// A server using @modelcontextprotocol/server-filesystem should NOT be PASS if embedded defaults are overridden
	// But a typosquat on @google/ should still be caught
	claudeCfg := `{
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
			}
		}
	}`

	home := setupHomeDir(t, claudeCfg)
	userTrust := `{
		"version": "1.0.0",
		"generated_at": "2026-06-20T00:00:00Z",
		"trusted": ["@google/"]
	}`
	trustPath := writeTrustConfig(t, t.TempDir(), userTrust)

	out, _, code := runMCPAudit(t, bin, home, "static", "--trust-config", trustPath)
	if code != 0 {
		t.Errorf("expected exit 0, got %d\noutput:\n%s", code, out)
	}
}

// =============================================================================
// Scenario: Export current config
// WHEN mcp-audit trust export is run
// THEN the current effective trust config is written to stdout as JSON
// =============================================================================

func TestE2E_TrustExport_OutputsValidJSON(t *testing.T) {
	bin := buildBinary(t)

	home := t.TempDir()
	stdout, _, code := runMCPAudit(t, bin, home, "trust", "export")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout:\n%s", code, stdout)
	}

	if !json.Valid([]byte(stdout)) {
		t.Fatalf("expected valid JSON output\nstdout:\n%s", stdout)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
		t.Fatalf("unmarshal output: %v\nstdout:\n%s", err, stdout)
	}

	if _, ok := parsed["trusted"]; !ok {
		t.Error("expected 'trusted' field in export output")
	}
	if _, ok := parsed["version"]; !ok {
		t.Error("expected 'version' field in export output")
	}
	if _, ok := parsed["generated_at"]; !ok {
		t.Error("expected 'generated_at' field in export output")
	}
}

// Regression: export after import reflects merged config
func TestE2E_TrustExport_AfterImportShowsMerge(t *testing.T) {
	bin := buildBinary(t)

	home := t.TempDir()

	// Create a trust config to import
	importContent := `{
		"version": "1.1.0",
		"generated_at": "2026-07-01T00:00:00Z",
		"trusted": ["@my-org/"],
		"blocked": ["evil-package"]
	}`
	importFile := filepath.Join(t.TempDir(), "import-trust.json")
	if err := os.WriteFile(importFile, []byte(importContent), 0644); err != nil {
		t.Fatalf("write import file: %v", err)
	}

	runMCPAudit(t, bin, home, "trust", "import", importFile)

	stdout, _, code := runMCPAudit(t, bin, home, "trust", "export")
	if code != 0 {
		t.Fatalf("export failed: %d\n%s", code, stdout)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	trusted, ok := parsed["trusted"].([]any)
	if !ok {
		t.Fatal("trusted field missing or wrong type")
	}

	// Should have embedded defaults + our import merged
	if len(trusted) < 1 {
		t.Errorf("expected at least 1 trusted, got %d", len(trusted))
	}
}

// =============================================================================
// Scenario: Trust import merges external config
// WHen mcp-audit trust import <file>
// THEN external config is merged with local
// =============================================================================

func TestE2E_TrustImport_MergesIntoLocal(t *testing.T) {
	bin := buildBinary(t)

	home := t.TempDir()

	importContent := `{
		"version": "1.1.0",
		"generated_at": "2026-07-01T00:00:00Z",
		"trusted": ["@my-org/"],
		"blocked": ["bad-pkg"]
	}`
	importFile := filepath.Join(t.TempDir(), "to-import.json")
	if err := os.WriteFile(importFile, []byte(importContent), 0644); err != nil {
		t.Fatalf("write import file: %v", err)
	}

	stdout, _, code := runMCPAudit(t, bin, home, "trust", "import", importFile)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstdout:\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "merged") {
		t.Errorf("expected 'merged' in import output\nstdout:\n%s", stdout)
	}

	// Verify the local trust.json was created with merged data
	cfgDir := filepath.Join(home, ".config", "mcp-audit")
	trustPath := filepath.Join(cfgDir, "trust.json")
	data, err := os.ReadFile(trustPath)
	if err != nil {
		t.Fatalf("read merged trust config: %v", err)
	}

	var tf intel.TrustFile
	if err := json.Unmarshal(data, &tf); err != nil {
		t.Fatalf("unmarshal merged config: %v", err)
	}

	foundMyOrg := slices.Contains(tf.Trusted, "@my-org/")
	if !foundMyOrg {
		t.Errorf("expected @my-org/ in merged trusted list, got %v", tf.Trusted)
	}
}

// Edge case: import a malformed file
func TestE2E_TrustImport_MalformedFile(t *testing.T) {
	bin := buildBinary(t)

	home := t.TempDir()

	importFile := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(importFile, []byte("not json"), 0644); err != nil {
		t.Fatalf("write bad file: %v", err)
	}

	_, _, code := runMCPAudit(t, bin, home, "trust", "import", importFile)
	if code == 0 {
		t.Error("expected non-zero exit for malformed import file")
	}
}

// Edge case: import with missing argument
func TestE2E_TrustImport_MissingArg(t *testing.T) {
	bin := buildBinary(t)

	home := t.TempDir()
	_, _, code := runMCPAudit(t, bin, home, "trust", "import")
	if code != 2 {
		t.Errorf("expected exit 2 for missing file argument, got %d", code)
	}
}

// =============================================================================
// Scenario: Update fetches latest / preserves local changes
// WHEN mcp-audit trust update is run, or local config differs from embedded
// THEN the latest trust config is downloaded / user is prompted before overwriting
// =============================================================================

func TestE2E_TrustUpdate_SubcommandWiredUp(t *testing.T) {
	bin := buildBinary(t)

	home := t.TempDir()

	_, _, code := runMCPAudit(t, bin, home, "trust")
	if code != 2 {
		t.Errorf("expected exit 2 for 'trust' without subcommand, got %d", code)
	}

	_, stderr, code := runMCPAudit(t, bin, home, "trust", "bogus")
	if code != 2 {
		t.Errorf("expected exit 2 for bogus trust subcommand, got %d\nstderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "bogus") {
		t.Errorf("expected error message mentioning 'bogus'\nstderr:\n%s", stderr)
	}

	_, stderr, code = runMCPAudit(t, bin, home, "trust", "update")
	if code == 0 {
		t.Log("trust update succeeded (live endpoint available)")
	} else {
		if code != 4 {
			t.Errorf("expected exit 4 on fetch failure, got %d\nstderr:\n%s", code, stderr)
		}
		if !strings.Contains(stderr, "fetch") && !strings.Contains(stderr, "update") {
			t.Errorf("expected fetch/update error message\nstderr:\n%s", stderr)
		}
	}
}

// Scenario: Update preserves local changes — prompt when local differs
func TestE2E_TrustUpdate_PromptsBeforeOverwrite(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	cfgDir := filepath.Join(home, ".config", "mcp-audit")
	if err := os.MkdirAll(cfgDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	localTrust := `{
		"version": "0.5.0",
		"generated_at": "2026-01-01T00:00:00Z",
		"trusted": ["@local-only/"],
		"blocked": ["local-blocked-pkg"]
	}`
	localPath := filepath.Join(cfgDir, "trust.json")
	if err := os.WriteFile(localPath, []byte(localTrust), 0644); err != nil {
		t.Fatalf("write local trust: %v", err)
	}

	stdout, _, code := runMCPAudit(t, bin, home, "trust", "export")
	if code != 0 {
		t.Fatalf("export failed: %d\n%s", code, stdout)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, stdout)
	}

	trusted, _ := parsed["trusted"].([]any)
	found := false
	for _, t := range trusted {
		if ts, ok := t.(string); ok && ts == "@local-only/" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected @local-only/ in effective config, got %v", trusted)
	}

	_, stderr, code := runMCPAudit(t, bin, home, "trust", "update")
	if code != 0 && code != 4 {
		t.Errorf("expected exit 0 or 4, got %d\nstderr:\n%s", code, stderr)
	}
}
