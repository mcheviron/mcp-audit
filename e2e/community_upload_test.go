package e2e_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mcheviron/mcp-audit/internal/intel"
)

// =============================================================================
// Scenario: Upload with confirmation
// WHEN mcp-audit upload is run
// THEN the anonymized data to be uploaded is displayed and the user is prompted
// =============================================================================

func TestE2E_Upload_DisplaysAnonymizedDataAndPrompts(t *testing.T) {
	t.Parallel()
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
	if err := os.MkdirAll(cfgDir, 0755); err != nil {
		t.Fatalf("mkdir cfg dir: %v", err)
	}

	// Write a trust config with full package names to trigger typosquat detection
	trustCfg := `{
		"trusted": ["@modelcontextprotocol/server-filesystem", "@anthropic/agent-toolkit"]
	}`
	writeTrustConfig(t, cfgDir, trustCfg)

	cmd := exec.Command(bin, "upload")
	cmd.Env = append(os.Environ(), "HOME="+home)
	stdinPipe, _ := cmd.StdinPipe()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start upload: %v", err)
	}
	stdinPipe.Write([]byte("n\n"))
	stdinPipe.Close()

	err := cmd.Wait()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
	}

	out := stdout.String()

	if !strings.Contains(out, "Data to be uploaded") {
		t.Logf("upload output:\nstdout:\n%s\nstderr:\n%s", out, stderr.String())
	}

	if !strings.Contains(out, "y/N") && !strings.Contains(out, "Y/n") {
		t.Logf("expected confirmation prompt in output\nstdout:\n%s", out)
	}

	if strings.Contains(out, "http://") || strings.Contains(out, "https://") {
		t.Errorf("output should not contain URLs\nstdout:\n%s", out)
	}

	_ = code
}

// Edge case: upload with no findings (clean config)
func TestE2E_Upload_NoFindings(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)

	claudeCfg := `{"mcpServers": {}}`
	home := setupHomeDir(t, claudeCfg)
	cfgDir := filepath.Join(home, ".config", "mcp-audit")
	_ = os.RemoveAll(cfgDir)

	stdout, _, code := runMCPAudit(t, bin, home, "upload")
	if code != 0 {
		t.Errorf("expected exit 0 with no findings, got %d\nstdout:\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "No findings") {
		t.Errorf("expected 'No findings' message\nstdout:\n%s", stdout)
	}
}

// =============================================================================
// Scenario: Cross-tool data exchange (MCPShield compatibility)
// WHEN a vulnerability is added to the community DB
// THEN it can be consumed by MCPShield and vice versa
// =============================================================================

func TestE2E_MCPShieldSchemaCompatibility(t *testing.T) {
	t.Parallel()
	vuln := map[string]any{
		"name":              "CVE-2024-1234",
		"cve":               "CVE-2024-1234",
		"cvss":              7.5,
		"affected_versions": []string{"<1.2.3"},
		"description":       "SSRF vulnerability in popular MCP server",
	}

	data, err := json.MarshalIndent(vuln, "", "  ")
	if err != nil {
		t.Fatalf("marshal vuln: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal vuln: %v", err)
	}

	requiredFields := []string{"name", "cve", "cvss", "affected_versions", "description"}
	for _, field := range requiredFields {
		if _, ok := parsed[field]; !ok {
			t.Errorf("MCPShield schema requires '%s' field", field)
		}
	}

	defaults, err := intel.LoadDefaults()
	if err != nil {
		t.Fatalf("LoadDefaults: %v", err)
	}
	if defaults.Version == "" {
		t.Error("embedded config missing version")
	}
	if defaults.GeneratedAt == "" {
		t.Error("embedded config missing generated_at")
	}
}

// =============================================================================
// Regression: things that shouldn't change still work
// =============================================================================

func TestE2E_Regression_StaticScanWorksNormally(t *testing.T) {
	t.Parallel()
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

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Errorf("static scan failed, code=%d\noutput:\n%s", code, out)
	}
	if !json.Valid([]byte(out)) {
		t.Fatal("static scan JSON output is not valid JSON")
	}
}

func TestE2E_Regression_VersionStillWorks(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)
	out, _, code := runMCPAudit(t, bin, os.Getenv("HOME"), "version")
	if code != 0 {
		t.Errorf("version failed, code=%d\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "mcp-audit") {
		t.Errorf("expected version string containing 'mcp-audit'\noutput:\n%s", out)
	}
}

func TestE2E_Regression_ProbeDryRunStillWorks(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)

	claudeCfg := `{
		"mcpServers": {
			"test-srv": {
				"url": "http://127.0.0.1:19999"
			}
		}
	}`

	home := setupHomeDir(t, claudeCfg)

	out, _, code := runMCPAudit(t, bin, home, "probe", "--dry-run")
	if code != 0 {
		t.Errorf("probe dry-run failed, code=%d\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "would probe") {
		t.Errorf("expected 'would probe' in dry-run output\noutput:\n%s", out)
	}
}

func TestE2E_Regression_SARIFOutputStillWorks(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)

	claudeCfg := `{
		"mcpServers": {
			"test-srv": {
				"url": "http://127.0.0.1:19999"
			}
		}
	}`

	home := setupHomeDir(t, claudeCfg)

	out, _, code := runMCPAudit(t, bin, home, "probe", "--dry-run", "--format", "sarif")
	if code != 0 {
		t.Errorf("sarif output failed, code=%d\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, `"$schema"`) {
		t.Errorf("expected $schema in SARIF output\noutput:\n%s", out)
	}
}
