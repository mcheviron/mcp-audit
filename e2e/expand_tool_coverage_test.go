package e2e_test

import (
	"runtime"
	"strings"
	"testing"

	"github.com/hashicorp/go-set"
)

func TestE2E_Expand_ClaudeCodeProjectMCPJSON(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		".mcp.json": `{
			"mcpServers": {
				"cc-project-server": {"command": "npx", "args": ["-y", "@scope/cc-proj-pkg"]}
			}
		}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}

	if !strings.Contains(out, "cc-project-server") {
		t.Error("expected cc-project-server from .mcp.json in CWD")
	}

	if !strings.Contains(out, ".mcp.json") && !strings.Contains(out, "mcp.json") {
		t.Error("expected .mcp.json config_path reference in output")
	}
}

func TestE2E_Expand_ClaudeCodeGlobalConfigFallback(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		".claude/mcp.json": `{
			"mcpServers": {
				"cc-global-server": {"command": "npx", "args": ["-y", "@scope/cc-global-pkg"]}
			}
		}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}

	if !strings.Contains(out, "cc-global-server") {
		t.Error("expected cc-global-server from ~/.claude/mcp.json")
	}
}

func TestE2E_Expand_ClaudeCodeBothProjectAndGlobal(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		".mcp.json": `{
			"mcpServers": {
				"shared-server": {"command": "npx", "args": ["-y", "@scope/project-version"]},
				"project-only": {"command": "npx", "args": ["-y", "@scope/proj-only"]}
			}
		}`,
		".claude/mcp.json": `{
			"mcpServers": {
				"shared-server": {"command": "npx", "args": ["-y", "@scope/global-version"]},
				"global-only": {"command": "node", "args": ["global.js"]}
			}
		}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}

	if !strings.Contains(out, "project-only") {
		t.Error("expected project-only server from .mcp.json")
	}

	if !strings.Contains(out, "shared-server") {
		t.Error("expected shared-server from .mcp.json")
	}
}

func TestE2E_Expand_ClineConfigExists(t *testing.T) {
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
		clineRel: `{
			"mcpServers": {
				"cline-srv": {"command": "npx", "args": ["-y", "@scope/cline-pkg"]}
			}
		}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}

	if !strings.Contains(out, "cline-srv") {
		t.Error("expected cline-srv from Cline MCP settings")
	}

	if !strings.Contains(out, "cline_mcp_settings.json") {
		t.Error("expected cline_mcp_settings.json in config_path reference")
	}
}

func TestE2E_Expand_ClineNotInstalled(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		"Library/Application Support/Claude/claude_desktop_config.json": `{
			"mcpServers": {
				"claude-srv": {"command": "npx", "args": ["-y", "@scope/claude-pkg"]}
			}
		}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0 when Cline not installed, got %d\n%s", code, out)
	}

	if !strings.Contains(out, "claude-srv") {
		t.Error("expected claude-srv even when Cline is not installed")
	}
}

func TestE2E_Expand_ClineMultipleServers(t *testing.T) {
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
		clineRel: `{
			"mcpServers": {
				"cline-a": {"command": "npx", "args": ["-y", "@scope/a"]},
				"cline-b": {"command": "node", "args": ["b.js"]},
				"cline-c": {"command": "python", "args": ["-m", "c"]}
			}
		}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json", "--no-project-config")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}

	for _, name := range []string{"cline-a", "cline-b", "cline-c"} {
		if !strings.Contains(out, name) {
			t.Errorf("expected server %q in output", name)
		}
	}

	findings := parseJSONFindings(t, out)
	seenCline := set.New[string](0)
	for _, f := range findings {
		if server, ok := f["server"].(string); ok {
			if server == "cline-a" || server == "cline-b" || server == "cline-c" {
				seenCline.Insert(server)
			}
		}
	}
	if seenCline.Size() != 3 {
		t.Errorf("expected 3 cline-roo servers, got %d", seenCline.Size())
	}
}

func TestE2E_Expand_CopilotCLIConfigExists(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		".copilot/mcp-config.json": `{
			"mcpServers": {
				"copilot-srv": {"command": "npx", "args": ["-y", "@scope/copilot-pkg"]}
			}
		}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}

	if !strings.Contains(out, "copilot-srv") {
		t.Error("expected copilot-srv from ~/.copilot/mcp-config.json")
	}

	if !strings.Contains(out, "mcp-config.json") {
		t.Error("expected mcp-config.json in config_path reference")
	}
}

func TestE2E_Expand_CopilotCLINotInstalled(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		"Library/Application Support/Claude/claude_desktop_config.json": `{
			"mcpServers": {
				"claude-srv": {"command": "npx", "args": ["-y", "@scope/claude-pkg"]}
			}
		}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0 when Copilot not installed, got %d\n%s", code, out)
	}

	if !strings.Contains(out, "claude-srv") {
		t.Error("expected claude-srv even when Copilot is not installed")
	}
}

func TestE2E_Expand_CopilotMixedStdioHTTP(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		".copilot/mcp-config.json": `{
			"mcpServers": {
				"copilot-stdio": {"command": "npx", "args": ["-y", "@scope/stdio-pkg"]},
				"copilot-http": {"url": "https://api.example.com/mcp"}
			}
		}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}

	if !strings.Contains(out, "copilot-stdio") {
		t.Error("expected copilot-stdio (command-based) in output")
	}
	if !strings.Contains(out, "copilot-http") {
		t.Error("expected copilot-http (url-based) in output")
	}
}

func TestE2E_Expand_GeminiProjectConfig(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		".mcp.json": `{
			"mcpServers": {
				"gemini-proj-srv": {"command": "npx", "args": ["-y", "@scope/gemini-proj-pkg"]}
			}
		}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}

	if !strings.Contains(out, "gemini-proj-srv") {
		t.Error("expected gemini-proj-srv from .mcp.json for Gemini")
	}

	if !strings.Contains(out, ".mcp.json") && !strings.Contains(out, "mcp.json") {
		t.Error("expected .mcp.json in config_path reference")
	}
}

func TestE2E_Expand_GeminiGlobalSettings(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		".gemini/settings.json": `{
			"mcpServers": {
				"gemini-global-srv": {"command": "npx", "args": ["-y", "@scope/gemini-global-pkg"]}
			}
		}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}

	if !strings.Contains(out, "gemini-global-srv") {
		t.Error("expected gemini-global-srv from ~/.gemini/settings.json")
	}

	if !strings.Contains(out, "settings.json") {
		t.Error("expected settings.json in config_path reference")
	}
}

func TestE2E_Expand_GeminiNotInstalled(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		"Library/Application Support/Claude/claude_desktop_config.json": `{
			"mcpServers": {}
		}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0 when Gemini not installed, got %d\n%s", code, out)
	}
	_ = out
}

func TestE2E_Expand_GeminiNestedMcpServers(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		".gemini/settings.json": `{
			"mcp": {
				"mcpServers": {
					"gemini-nested-srv": {"command": "npx", "args": ["-y", "@scope/gemini-nested-pkg"]}
				}
			}
		}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}

	if !strings.Contains(out, "gemini-nested-srv") {
		t.Error("expected gemini-nested-srv from nested mcp.mcpServers in settings.json")
	}
}

func TestE2E_Expand_ZedUnderscoreKey(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		".config/zed/settings.json": `{
			"mcp_servers": {
				"zed-underscore-srv": {"command": "npx", "args": ["-y", "@scope/zed-under-pkg"]}
			}
		}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}

	if !strings.Contains(out, "zed-underscore-srv") {
		t.Error("expected zed-underscore-srv from mcp_servers key")
	}

	if !strings.Contains(out, "settings.json") {
		t.Error("expected settings.json in config_path reference")
	}
}

func TestE2E_Expand_ZedCamelCaseKey(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		".config/zed/settings.json": `{
			"mcpServers": {
				"zed-camel-srv": {"command": "npx", "args": ["-y", "@scope/zed-camel-pkg"]}
			}
		}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}

	if !strings.Contains(out, "zed-camel-srv") {
		t.Error("expected zed-camel-srv from mcpServers key")
	}
}

func TestE2E_Expand_EmptyMcpServersInConfig(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		".copilot/mcp-config.json": `{
			"mcpServers": {}
		}`,
		".mcp.json": `{
			"mcpServers": {}
		}`,
		".claude/mcp.json": `{
			"mcpServers": {}
		}`,
		".config/zed/settings.json": `{
			"mcpServers": {}
		}`,
		".gemini/settings.json": `{
			"mcpServers": {}
		}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0 with empty mcpServers, got %d\n%s", code, out)
	}

	findings := parseJSONFindings(t, out)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings with all empty mcpServers, got %d", len(findings))
	}
}

func TestE2E_Expand_ZedUnderscoreParsedIdentically(t *testing.T) {
	bin := buildBinary(t)
	home1 := t.TempDir()
	home2 := t.TempDir()

	writeFiles(t, home1, map[string]string{
		".config/zed/settings.json": `{
			"mcp_servers": {
				"identical-srv": {"command": "npx", "args": ["-y", "@scope/test-pkg"]}
			}
		}`,
	})

	writeFiles(t, home2, map[string]string{
		".config/zed/settings.json": `{
			"mcpServers": {
				"identical-srv": {"command": "npx", "args": ["-y", "@scope/test-pkg"]}
			}
		}`,
	})

	out1, _, code1 := runMCPAudit(t, bin, home1, "static", "--format", "json", "--no-project-config")
	out2, _, code2 := runMCPAudit(t, bin, home2, "static", "--format", "json", "--no-project-config")

	if code1 != 0 || code2 != 0 {
		t.Fatalf("expected exit 0, got %d and %d\n%s\n%s", code1, code2, out1, out2)
	}

	f1 := parseJSONFindings(t, out1)
	f2 := parseJSONFindings(t, out2)

	count1 := 0
	for _, f := range f1 {
		if server, ok := f["server"].(string); ok && server == "identical-srv" {
			count1++
			break
		}
	}
	count2 := 0
	for _, f := range f2 {
		if server, ok := f["server"].(string); ok && server == "identical-srv" {
			count2++
			break
		}
	}

	if count1 != 1 || count2 != 1 {
		t.Errorf("expected exactly 1 'identical-srv' in both variants; underscore=%d, camelCase=%d", count1, count2)
	}
}
