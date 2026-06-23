package e2e_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestE2E_CVE_RegressionVersion(t *testing.T) {
	bin := buildBinary(t)

	out, _, code := runMCPAudit(t, bin, os.Getenv("HOME"), "version")
	if code != 0 {
		t.Fatalf("version failed: %d\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "mcp-audit") {
		t.Errorf("expected 'mcp-audit' in version output, got: %s", out)
	}
}

func TestE2E_CVE_RegressionTyposquatStillWorks(t *testing.T) {
	bin := buildBinary(t)

	claudeCfg := `{
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesytem", "/tmp"]
			}
		}
	}`

	home := setupHomeDir(t, claudeCfg)
	trustCfg := writeTrustConfig(t, t.TempDir(), `{
		"trusted": ["@modelcontextprotocol/server-filesystem"]
	}`)

	out, _, code := runMCPAudit(t, bin, home, "static", "--trust-config", trustCfg)
	if code != 0 {
		t.Errorf("expected exit 0 for typosquat detection, got %d\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "typosquat") {
		t.Errorf("expected typosquat detection in output\noutput:\n%s", out)
	}
}

func TestE2E_CVE_RegressionProbeDryRun(t *testing.T) {
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
		t.Errorf("expected exit 0 for probe dry-run, got %d\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "would probe") {
		t.Errorf("expected 'would probe' in output\noutput:\n%s", out)
	}
}

func TestE2E_CVE_RegressionScan(t *testing.T) {
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
	_, _, code := runMCPAudit(t, bin, home, "scan", "--dry-run", "--no-cve-scan")
	if code == 2 {
		t.Errorf("scan with --dry-run and --no-cve-scan exited with error code 2")
	}
}

func TestE2E_CVE_RegressionJSONOutput(t *testing.T) {
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
	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json", "--no-color")
	if code != 0 {
		t.Fatalf("json output failed: %d\noutput:\n%s", code, out)
	}

	var data struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &data); err != nil {
		t.Fatalf("invalid JSON output: %v\noutput:\n%s", err, out)
	}
	if len(data.Findings) == 0 {
		t.Error("expected non-empty findings array")
	}
}

func TestE2E_CVE_RegressionAllFormats(t *testing.T) {
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

	for _, tc := range []struct {
		format, want string
	}{
		{"json", `"severity"`},
		{"sarif", `"$schema"`},
		{"junit", "testsuite"},
	} {
		t.Run(tc.format, func(t *testing.T) {
			out, _, code := runMCPAudit(t, bin, home, "static", "--format", tc.format, "--no-color", "--no-cve-scan")
			if code != 0 {
				t.Errorf("exit %d for format %s\noutput:\n%s", code, tc.format, out)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("expected %q in %s output\noutput:\n%s", tc.want, tc.format, out)
			}
		})
	}
}

func TestE2E_CVE_RegressionOutputFile(t *testing.T) {
	bin := buildBinary(t)

	claudeCfg := `{"mcpServers": {"filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]}}}`
	home := setupHomeDir(t, claudeCfg)
	outFile := filepath.Join(t.TempDir(), "report.json")

	_, _, code := runMCPAudit(t, bin, home, "static", "--format", "json", "--no-color", "--output-file", outFile)
	if code != 0 {
		t.Fatalf("run failed: %d", code)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}

	var report struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("parse output file: %v\ncontent:\n%s", err, string(data))
	}
	if len(report.Findings) == 0 {
		t.Error("output file has no findings")
	}
}

func TestE2E_CVE_RegressionNoColor(t *testing.T) {
	bin := buildBinary(t)

	claudeCfg := `{"mcpServers": {"filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]}}}`
	home := setupHomeDir(t, claudeCfg)
	out, _, code := runMCPAudit(t, bin, home, "static", "--no-color")
	if code != 0 {
		t.Fatalf("run failed: %d\noutput:\n%s", code, out)
	}

	if strings.Contains(out, "\033[") {
		t.Error("output contains ANSI escape codes despite --no-color")
	}
}

func TestE2E_CVE_RegressionCorruptedConfig(t *testing.T) {
	bin := buildBinary(t)

	home := t.TempDir()

	claudeDir := filepath.Join(home, "Library", "Application Support", "Claude")
	if err := os.MkdirAll(claudeDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(claudeDir, "claude_desktop_config.json"),
		[]byte(`{invalid json`), 0644,
	); err != nil {
		t.Fatalf("write config: %v", err)
	}

	out, _, code := runMCPAudit(t, bin, home, "static", "--no-color")
	if code == 2 {
		t.Errorf("scan exited with error code 2 on corrupted config\noutput:\n%s", out)
	}
}
