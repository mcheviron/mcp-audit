package e2e_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestE2E_Expand_ZedNotInstalled(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		"Library/Application Support/Claude/claude_desktop_config.json": `{
			"mcpServers": {}
		}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0 when Zed not installed, got %d\n%s", code, out)
	}
	_ = out
}

func TestE2E_Expand_AllToolsConfigured(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	var clineRel string
	switch runtime.GOOS {
	case "darwin":
		clineRel = "Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"
	case "linux":
		clineRel = ".config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"
	default:
		clineRel = "AppData/Roaming/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"
	}

	writeFiles(t, home, map[string]string{
		"Library/Application Support/Claude/claude_desktop_config.json": `{
			"mcpServers": {"claude-desktop-srv": {"command": "npx", "args": ["-y", "@scope/claude-dt-pkg"]}}
		}`,
		".cursor/mcp.json": `{
			"mcpServers": {"cursor-srv": {"command": "npx", "args": ["-y", "@scope/cursor-pkg"]}}
		}`,
		".vscode/mcp.json": `{
			"mcpServers": {"vscode-srv": {"command": "npx", "args": ["-y", "@scope/vscode-pkg"]}}
		}`,
		".copilot/mcp-config.json": `{
			"mcpServers": {"copilot-srv": {"command": "npx", "args": ["-y", "@scope/copilot-pkg"]}}
		}`,
		".mcp.json": `{
			"mcpServers": {"claude-code-srv": {"command": "npx", "args": ["-y", "@scope/cc-pkg"]}}
		}`,
		clineRel: `{
			"mcpServers": {"cline-srv": {"command": "npx", "args": ["-y", "@scope/cline-pkg"]}}
		}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}

	expected := []string{"claude-desktop-srv", "cursor-srv", "vscode-srv", "copilot-srv", "claude-code-srv", "cline-srv"}
	for _, name := range expected {
		if !strings.Contains(out, name) {
			t.Errorf("expected server %q in output when all tools configured", name)
		}
	}

	findings := parseJSONFindings(t, out)
	if len(findings) == 0 {
		t.Error("expected some findings when all tools configured")
	}
}

func TestE2E_Expand_NoConfigsFound(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	out, stderr, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0 for no configs, got %d\nstderr: %s", code, stderr)
	}

	findings := parseJSONFindings(t, out)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings with no configs, got %d", len(findings))
	}
}

func TestE2E_Expand_PartialConfigOneToolMissing(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		".cursor/mcp.json": `{
			"mcpServers": {"cursor-srv": {"command": "npx", "args": ["-y", "@scope/cursor-pkg"]}}
		}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}

	if !strings.Contains(out, "cursor-srv") {
		t.Error("expected cursor-srv when Claude Desktop config is missing")
	}
}

func TestE2E_Expand_CodexTOMLDiscovered(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		filepath.Join("Library", "Application Support", "Codex", "config.toml"): `
[mcp_servers.codex-toml-srv]
command = "npx"
args = ["-y", "@scope/codex-pkg"]
`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}

	if !strings.Contains(out, "codex-toml-srv") {
		t.Error("expected codex-toml-srv from TOML discovery")
	}
}

func TestE2E_Expand_MalformedConfigDoesNotCrash(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		".copilot/mcp-config.json": `{this is not valid json {{{`,
		".mcp.json":                `{bad json`,
		".claude/mcp.json":         `not even json`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code == 2 {
		t.Fatalf("scan error exit code 2 with all malformed configs\n%s", out)
	}
}

func TestE2E_Expand_RegressionStaticScanStillWorks(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		"Library/Application Support/Claude/claude_desktop_config.json": `{
			"mcpServers": {
				"filesystem": {
					"command": "npx",
					"args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
				}
			}
		}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}
	if !strings.Contains(out, "PASS") {
		t.Error("expected PASS for known trusted package in regression test")
	}
}

func TestE2E_Expand_RegressionProbeDryRunStillWorks(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		"Library/Application Support/Claude/claude_desktop_config.json": `{
			"mcpServers": {}
		}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "probe", "--dry-run")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}
}

func TestE2E_Expand_RegressionVersionStillWorks(t *testing.T) {
	bin := buildBinary(t)
	out, _, code := runMCPAudit(t, bin, os.Getenv("HOME"), "version")
	if code != 0 {
		t.Fatalf("expected exit 0 for version, got %d\n%s", code, out)
	}
	if !strings.Contains(out, "mcp-audit") {
		t.Error("expected version string in output")
	}
}

func TestE2E_Expand_RegressionSARIFOutputWorks(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		"Library/Application Support/Claude/claude_desktop_config.json": `{
			"mcpServers": {}
		}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "sarif")
	if code != 0 {
		t.Fatalf("expected exit 0 for SARIF, got %d\n%s", code, out)
	}
	if !strings.Contains(out, `"$schema"`) {
		t.Error("expected $schema in SARIF output")
	}
}

func TestE2E_Expand_CorruptedGeminiSettingsDoesNotCrash(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		".gemini/settings.json": `[[[broken json {{{ !!!`,
		"Library/Application Support/Claude/claude_desktop_config.json": `{
			"mcpServers": {"claude-srv": {"command": "npx", "args": ["-y", "@scope/pkg"]}}
		}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0 with corrupted Gemini settings, got %d\n%s", code, out)
	}

	if !strings.Contains(out, "claude-srv") {
		t.Error("expected claude-srv even with corrupted Gemini settings")
	}
}

func TestE2E_Expand_CorruptedZedSettingsDoesNotCrash(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		".config/zed/settings.json": `not valid json {{{`,
		"Library/Application Support/Claude/claude_desktop_config.json": `{
			"mcpServers": {"claude-srv": {"command": "npx", "args": ["-y", "@scope/pkg"]}}
		}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0 with corrupted Zed settings, got %d\n%s", code, out)
	}

	if !strings.Contains(out, "claude-srv") {
		t.Error("expected claude-srv even with corrupted Zed settings")
	}
}

func TestE2E_Expand_CorruptedClineSettingsDoesNotCrash(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("platform-specific Cline path test")
	}

	bin := buildBinary(t)
	home := t.TempDir()

	var clineRel string
	switch runtime.GOOS {
	case "darwin":
		clineRel = "Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"
	case "linux":
		clineRel = ".config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"
	default:
		clineRel = "AppData/Roaming/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"
	}

	writeFiles(t, home, map[string]string{
		clineRel: `{{{ bad json`,
		"Library/Application Support/Claude/claude_desktop_config.json": `{
			"mcpServers": {"claude-srv": {"command": "npx", "args": ["-y", "@scope/pkg"]}}
		}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0 with corrupted Cline settings, got %d\n%s", code, out)
	}

	if !strings.Contains(out, "claude-srv") {
		t.Error("expected claude-srv even with corrupted Cline settings")
	}
}

func TestE2E_Expand_GeminiTopLevelWinsOverNested(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		".gemini/settings.json": `{
			"mcpServers": {
				"top-level-srv": {"command": "npx", "args": ["-y", "@scope/top-pkg"]}
			},
			"mcp": {
				"mcpServers": {
					"nested-srv": {"command": "node", "args": ["nested.js"]}
				}
			}
		}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}

	if !strings.Contains(out, "top-level-srv") {
		t.Error("expected top-level-srv from top-level mcpServers")
	}

	if strings.Contains(out, "nested-srv") {
		t.Error("expected nested-srv NOT to appear when top-level mcpServers exists (top-level wins)")
	}
}

func TestE2E_Expand_ZedUnderscoreSameAsCamelCaseOutput(t *testing.T) {
	bin := buildBinary(t)
	homeU := t.TempDir()
	homeC := t.TempDir()

	writeFiles(t, homeU, map[string]string{
		".config/zed/settings.json": `{
			"mcp_servers": {
				"server-a": {"command": "npx", "args": ["-y", "@scope/a"]},
				"server-b": {"url": "https://b.example.com/mcp"}
			}
		}`,
	})

	writeFiles(t, homeC, map[string]string{
		".config/zed/settings.json": `{
			"mcpServers": {
				"server-a": {"command": "npx", "args": ["-y", "@scope/a"]},
				"server-b": {"url": "https://b.example.com/mcp"}
			}
		}`,
	})

	outU, _, codeU := runMCPAudit(t, bin, homeU, "static", "--format", "json", "--no-project-config")
	outC, _, codeC := runMCPAudit(t, bin, homeC, "static", "--format", "json", "--no-project-config")

	if codeU != 0 {
		t.Fatalf("underscore variant exit %d\n%s", codeU, outU)
	}
	if codeC != 0 {
		t.Fatalf("camelCase variant exit %d\n%s", codeC, outC)
	}

	fU := parseJSONFindings(t, outU)
	fC := parseJSONFindings(t, outC)

	if len(fU) != len(fC) {
		t.Errorf("expected same number of findings: underscore=%d, camelCase=%d", len(fU), len(fC))
	}

	countServer := func(findings []map[string]any, name string) int {
		for _, f := range findings {
			if server, ok := f["server"].(string); ok && server == name {
				return 1
			}
		}
		return 0
	}

	for _, name := range []string{"server-a", "server-b"} {
		cu := countServer(fU, name)
		cc := countServer(fC, name)
		if cu != 1 || cc != 1 {
			t.Errorf("expected exactly 1 %q in both variants; underscore=%d, camelCase=%d", name, cu, cc)
		}
	}
}

func TestE2E_Expand_MixedAllNewToolsRegression(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	var clineRel string
	switch runtime.GOOS {
	case "darwin":
		clineRel = "Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"
	case "linux":
		clineRel = ".config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"
	default:
		clineRel = "AppData/Roaming/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"
	}

	writeFiles(t, home, map[string]string{
		"Library/Application Support/Claude/claude_desktop_config.json": `{
			"mcpServers": {"claude-srv": {"command": "npx", "args": ["-y", "@scope/claude-pkg"]}}
		}`,
		".mcp.json": `{
			"mcpServers": {"cc-proj-srv": {"command": "npx", "args": ["-y", "@scope/cc-proj-pkg"]}}
		}`,
		".copilot/mcp-config.json": `{
			"mcpServers": {"copilot-srv": {"url": "https://api.example.com/mcp"}}
		}`,
		".gemini/settings.json": `{
			"mcpServers": {"gemini-srv": {"command": "python", "args": ["server.py"]}}
		}`,
		".config/zed/settings.json": `{
			"mcp_servers": {"zed-srv": {"command": "node", "args": ["server.js"]}}
		}`,
		clineRel: `{
			"mcpServers": {"cline-srv": {"command": "npx", "args": ["-y", "@scope/cline-pkg"]}}
		}`,
		"Library/Application Support/Codex/config.toml": `
[mcp_servers.codex-srv]
command = "npx"
args = ["-y", "@scope/codex-pkg"]
`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}

	expectedServers := []string{
		"claude-srv", "cc-proj-srv", "copilot-srv",
		"zed-srv", "cline-srv", "codex-srv",
	}
	for _, name := range expectedServers {
		if !strings.Contains(out, name) {
			t.Errorf("expected server %q in mixed-all-tools output", name)
		}
	}

	findings := parseJSONFindings(t, out)
	if len(findings) == 0 {
		t.Error("expected some findings when all tools configured")
	}
}

func TestE2E_Expand_ConfigPathValidation(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		".copilot/mcp-config.json": `{
			"mcpServers": {"cp-srv": {"command": "npx", "args": ["-y", "@scope/pkg"]}}
		}`,
		".mcp.json": `{
			"mcpServers": {"cc-srv": {"command": "npx", "args": ["-y", "@scope/pkg"]}}
		}`,
		".claude/mcp.json": `{
			"mcpServers": {"cc-global-srv": {"command": "npx", "args": ["-y", "@scope/pkg"]}}
		}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}

	findings := parseJSONFindings(t, out)
	if len(findings) == 0 {
		t.Fatal("expected some findings")
	}

	for _, f := range findings {
		configPath, ok := f["config_path"].(string)
		if !ok || configPath == "" {
			serverName, _ := f["server"].(string)
			t.Errorf("expected non-empty config_path for server %q", serverName)
		}
	}
}
