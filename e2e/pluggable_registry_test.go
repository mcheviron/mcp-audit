package e2e_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for path, content := range files {
		fullPath := filepath.Join(dir, path)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(fullPath), err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
}

func writeToolsJSON(t *testing.T, home string, tools []map[string]any) string {
	t.Helper()
	mcpAuditDir := filepath.Join(home, ".config", "mcp-audit")
	if err := os.MkdirAll(mcpAuditDir, 0755); err != nil {
		t.Fatalf("mkdir mcp-audit dir: %v", err)
	}
	data, err := json.Marshal(map[string]any{"tools": tools})
	if err != nil {
		t.Fatalf("marshal tools.json: %v", err)
	}
	path := filepath.Join(mcpAuditDir, "tools.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write tools.json: %v", err)
	}
	return path
}

func writeCustomToolsJSON(t *testing.T, dir string, tools []map[string]any) string {
	t.Helper()
	data, err := json.Marshal(map[string]any{"tools": tools})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(dir, "custom-tools.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write custom-tools.json: %v", err)
	}
	return path
}

func TestE2E_AllBuiltinToolsConfigured(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		"Library/Application Support/Claude/claude_desktop_config.json": `{
			"mcpServers": {
				"claude-server": {"command": "npx", "args": ["-y", "@scope/claude-pkg"]}
			}
		}`,
		".cursor/mcp.json": `{
			"mcpServers": {
				"cursor-server": {"command": "npx", "args": ["-y", "@scope/cursor-pkg"]}
			}
		}`,
		".vscode/mcp.json": `{
			"mcpServers": {
				"vscode-server": {"command": "npx", "args": ["-y", "@scope/vscode-pkg"]}
			}
		}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr:\n%s", code, out)
	}

	if !strings.Contains(out, "claude-server") {
		t.Error("expected claude-server in output")
	}
	if !strings.Contains(out, "cursor-server") {
		t.Error("expected cursor-server in output")
	}
	if !strings.Contains(out, "vscode-server") {
		t.Error("expected vscode-server in output")
	}

	findings := parseJSONFindings(t, out)
	countMap := make(map[string]int)
	for _, f := range findings {
		if server, ok := f["server"].(string); ok {
			countMap[server]++
		}
	}

	for _, name := range []string{"claude-server", "cursor-server", "vscode-server"} {
		if countMap[name] == 0 {
			t.Errorf("expected finding for server %q", name)
		}
	}
}

func TestE2E_UserDefinedToolDiscovered(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	myToolCfgDir := filepath.Join(home, ".my-tool")
	if err := os.MkdirAll(myToolCfgDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	writeFiles(t, home, map[string]string{
		".my-tool/mcp.json": `{
			"mcpServers": {
				"my-server": {"command": "npx", "args": ["-y", "my-package"]}
			}
		}`,
	})

	writeToolsJSON(t, home, []map[string]any{
		{
			"name":       "my-tool",
			"format":     "json",
			"server_key": "mcpServers",
			"paths":      []string{filepath.Join(home, ".my-tool", "mcp.json")},
		},
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}

	if !strings.Contains(out, "my-server") {
		t.Error("expected my-server from user-defined tool to appear in output")
	}
}

func TestE2E_NoConfigsFound(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		".config/mcp-audit/tools.json": `{"tools": [{"name": "nonexistent", "format": "json", "server_key": "mcpServers", "paths": ["/nonexistent/path/mcp.json"]}]}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0 for no configs found, got %d\n%s", code, out)
	}

	if strings.Contains(out, "nonexistent") {
		t.Error("expected no servers found when no config files exist")
	}
}

func TestE2E_PartialConfigOneToolMissing(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		".cursor/mcp.json": `{
			"mcpServers": {
				"cursor-server": {"command": "npx", "args": ["-y", "@scope/cursor-pkg"]}
			}
		}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}

	if !strings.Contains(out, "cursor-server") {
		t.Error("expected cursor-server in output even when Claude config is missing")
	}

	if strings.Contains(out, "claude-server") {
		t.Error("expected no claude-server since Claude config is absent")
	}
}

func TestE2E_TOMLFormatToolDiscovered(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	codexDir := filepath.Join(home, "Library", "Application Support", "Codex")
	if err := os.MkdirAll(codexDir, 0755); err != nil {
		t.Fatalf("mkdir codex: %v", err)
	}
	codexToml := `
[mcp_servers.codex-server]
command = "npx"
args = ["-y", "@scope/codex-pkg"]
`
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(codexToml), 0644); err != nil {
		t.Fatalf("write codex config.toml: %v", err)
	}

	userTomlToolDir := filepath.Join(home, ".user-toml-tool")
	if err := os.MkdirAll(userTomlToolDir, 0755); err != nil {
		t.Fatalf("mkdir user-toml-tool: %v", err)
	}
	userToml := `
[mcp_servers.user-toml-server]
command = "node"
args = ["server.js"]
`
	if err := os.WriteFile(filepath.Join(userTomlToolDir, "config.toml"), []byte(userToml), 0644); err != nil {
		t.Fatalf("write user toml: %v", err)
	}

	writeToolsJSON(t, home, []map[string]any{
		{
			"name":       "user-toml-app",
			"format":     "toml",
			"server_key": "mcpServers",
			"paths":      []string{filepath.Join(userTomlToolDir, "config.toml")},
		},
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}

	if !strings.Contains(out, "codex-server") {
		t.Error("expected codex-server from built-in Codex TOML parser")
	}
	if !strings.Contains(out, "user-toml-server") {
		t.Error("expected user-toml-server from user TOML-format tool")
	}
}

func TestE2E_UserToolsMergeBeforeDiscovery(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		"Library/Application Support/Claude/claude_desktop_config.json": `{
			"mcpServers": {
				"claude-server": {"command": "npx", "args": ["-y", "@scope/claude-pkg"]}
			}
		}`,
	})

	writeToolsJSON(t, home, []map[string]any{
		{
			"name":       "merged-tool",
			"format":     "json",
			"server_key": "mcpServers",
			"paths":      []string{filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")},
		},
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}

	claudeCount := strings.Count(out, "claude-server")
	if claudeCount < 1 {
		t.Errorf("expected claude-server from merged registry; claude-server appeared %d times", claudeCount)
	}
}

func TestE2E_TOMLStdioServer(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	codexDir := filepath.Join(home, "Library", "Application Support", "Codex")
	if err := os.MkdirAll(codexDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	codexToml := `
[mcp_servers.my-stdio-server]
command = "npx"
args = ["-y", "@scope/pkg"]
`
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(codexToml), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}

	if !strings.Contains(out, "my-stdio-server") {
		t.Error("expected my-stdio-server in output")
	}

	findings := parseJSONFindings(t, out)
	found := false
	for _, f := range findings {
		if server, ok := f["server"].(string); ok && server == "my-stdio-server" {
			found = true
			if configPath, ok := f["config_path"].(string); ok {
				if !strings.Contains(configPath, "config.toml") {
					t.Errorf("expected config_path to reference config.toml, got %q", configPath)
				}
			}
		}
	}
	if !found {
		t.Error("expected finding for my-stdio-server")
	}
}

func TestE2E_TOMLStreamableHTTPServer(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	codexDir := filepath.Join(home, "Library", "Application Support", "Codex")
	if err := os.MkdirAll(codexDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	codexToml := `
[mcp_servers.remote-http]
url = "https://example.com/mcp"
`
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(codexToml), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}

	if !strings.Contains(out, "remote-http") {
		t.Error("expected remote-http server in output")
	}

	findings := parseJSONFindings(t, out)
	found := false
	for _, f := range findings {
		if server, ok := f["server"].(string); ok && server == "remote-http" {
			found = true
		}
	}
	if !found {
		t.Error("expected finding for remote-http")
	}
}

func TestE2E_TOMLServerWithAuthEnvVar(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	codexDir := filepath.Join(home, "Library", "Application Support", "Codex")
	if err := os.MkdirAll(codexDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	codexToml := `
[mcp_servers.auth-server]
command = "node"
args = ["server.js"]
bearer_token_env_var = "E2E_AUTH_TOKEN"
`
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(codexToml), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	t.Setenv("E2E_AUTH_TOKEN", "secret-token-value")

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}

	if !strings.Contains(out, "auth-server") {
		t.Error("expected auth-server in output")
	}
}

func TestE2E_TOMLServerWithCustomHeaders(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	codexDir := filepath.Join(home, "Library", "Application Support", "Codex")
	if err := os.MkdirAll(codexDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	codexToml := `
[mcp_servers.header-server]
command = "echo"
http_headers = { X-Custom = "val123" }
`
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(codexToml), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}

	if !strings.Contains(out, "header-server") {
		t.Error("expected header-server in output")
	}
}

func TestE2E_TOMLServerWithEnvVars(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	codexDir := filepath.Join(home, "Library", "Application Support", "Codex")
	if err := os.MkdirAll(codexDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	codexToml := `
[mcp_servers.env-server]
command = "python"
env = { NODE_ENV = "production", PORT = "3000" }
`
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(codexToml), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}

	if !strings.Contains(out, "env-server") {
		t.Error("expected env-server in output")
	}
}

func TestE2E_TOMLMalformedConfig(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	codexDir := filepath.Join(home, "Library", "Application Support", "Codex")
	if err := os.MkdirAll(codexDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	codexToml := `this is not valid toml {{{`
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(codexToml), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	out, stderr, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code == 2 {
		t.Fatalf("scan error exit code 2 with malformed TOML\nstderr:\n%s", stderr)
	}

	findings := parseJSONFindings(t, out)
	for _, f := range findings {
		if server, ok := f["server"].(string); ok && server == "codex-server" {
			t.Errorf("expected no codex servers parsed from malformed TOML, got: %v", f)
		}
	}
}

func TestE2E_TOMLEmptyConfig(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	codexDir := filepath.Join(home, "Library", "Application Support", "Codex")
	if err := os.MkdirAll(codexDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(""), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0 for empty TOML config, got %d\n%s", code, out)
	}
}

func TestE2E_CodexMacOSPath(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-specific test")
	}

	bin := buildBinary(t)
	home := t.TempDir()

	codexDir := filepath.Join(home, "Library", "Application Support", "Codex")
	if err := os.MkdirAll(codexDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	codexToml := `
[mcp_servers.macos-codex-server]
command = "npx"
args = ["-y", "@scope/macos-pkg"]
`
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(codexToml), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}

	if !strings.Contains(out, "macos-codex-server") {
		t.Errorf("expected macos-codex-server discovered at macOS Codex path\noutput:\n%s", out)
	}
}

func TestE2E_UserAddsNewTool(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	myToolCfgDir := filepath.Join(home, ".cool-new-tool")
	if err := os.MkdirAll(myToolCfgDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeFiles(t, home, map[string]string{
		".cool-new-tool/mcp.json": `{
			"mcpServers": {
				"cool-server": {"command": "npx", "args": ["-y", "cool-package"]}
			}
		}`,
	})

	writeToolsJSON(t, home, []map[string]any{
		{
			"name":       "cool-new-tool",
			"format":     "json",
			"server_key": "mcpServers",
			"paths":      []string{filepath.Join(home, ".cool-new-tool", "mcp.json")},
		},
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}

	if !strings.Contains(out, "cool-server") {
		t.Error("expected cool-server from user-registered 'cool-new-tool'")
	}
}

func TestE2E_UserOverridesBuiltinTool(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	customCursorDir := filepath.Join(home, ".my-custom-cursor")
	if err := os.MkdirAll(customCursorDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeFiles(t, home, map[string]string{
		".my-custom-cursor/mcp.json": `{
			"mcpServers": {
				"custom-cursor-server": {"command": "npx", "args": ["-y", "custom-cursor-pkg"]}
			}
		}`,
	})

	writeToolsJSON(t, home, []map[string]any{
		{
			"name":       "cursor",
			"format":     "json",
			"server_key": "mcpServers",
			"paths":      []string{filepath.Join(home, ".my-custom-cursor", "mcp.json")},
		},
	})

	out, stderr, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}

	if !strings.Contains(stderr, "user tool") || !strings.Contains(stderr, "overrides") {
		t.Errorf("expected 'user tool overrides' warning in stderr\nstderr:\n%s", stderr)
	}

	if !strings.Contains(stderr, "cursor") {
		t.Errorf("expected 'cursor' name in override warning\nstderr:\n%s", stderr)
	}
}

func TestE2E_MalformedToolsJSON(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		"Library/Application Support/Claude/claude_desktop_config.json": `{
			"mcpServers": {
				"claude-server": {"command": "npx", "args": ["-y", "@scope/claude-pkg"]}
			}
		}`,
		".config/mcp-audit/tools.json": `{this is not valid json`,
	})

	out, stderr, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0 with malformed tools.json, got %d\nstderr:\n%s", code, stderr)
	}

	if !strings.Contains(out, "claude-server") {
		t.Error("expected built-in claude-server still discovered with malformed tools.json")
	}

	if !strings.Contains(stderr, "malformed") || !strings.Contains(stderr, "built-in") {
		t.Errorf("expected 'malformed ... built-in tools only' warning\nstderr:\n%s", stderr)
	}
}

func TestE2E_MissingToolsJSON(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		"Library/Application Support/Claude/claude_desktop_config.json": `{
			"mcpServers": {
				"claude-server": {"command": "npx", "args": ["-y", "@scope/claude-pkg"]}
			}
		}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0 without tools.json, got %d\n%s", code, out)
	}

	if !strings.Contains(out, "claude-server") {
		t.Error("expected built-in claude-server discovered without tools.json")
	}
}

func TestE2E_CustomToolsConfigPath(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	myToolCfgDir := filepath.Join(home, ".custom-tool-app")
	if err := os.MkdirAll(myToolCfgDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeFiles(t, home, map[string]string{
		".custom-tool-app/mcp.json": `{
			"mcpServers": {
				"custom-path-server": {"command": "npx", "args": ["-y", "custom-path-pkg"]}
			}
		}`,
	})

	customDir := t.TempDir()
	toolsPath := writeCustomToolsJSON(t, customDir, []map[string]any{
		{
			"name":       "custom-path-tool",
			"format":     "json",
			"server_key": "mcpServers",
			"paths":      []string{filepath.Join(home, ".custom-tool-app", "mcp.json")},
		},
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json", "--tools-config", toolsPath)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}

	if !strings.Contains(out, "custom-path-server") {
		t.Error("expected custom-path-server from --tools-config path")
	}
}

func TestE2E_UserToolOverridesBuiltinWithWarning(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	customCurDir := filepath.Join(home, ".custom-cur")
	if err := os.MkdirAll(customCurDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeFiles(t, home, map[string]string{
		".custom-cur/mcp.json": `{
			"mcpServers": {
				"override-server": {"command": "npx", "args": ["-y", "override-pkg"]}
			}
		}`,
	})

	writeToolsJSON(t, home, []map[string]any{
		{
			"name":       "cursor",
			"format":     "json",
			"server_key": "mcpServers",
			"paths":      []string{filepath.Join(home, ".custom-cur", "mcp.json")},
		},
	})

	_, stderr, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr:\n%s", code, stderr)
	}

	if !strings.Contains(stderr, "user tool") || !strings.Contains(stderr, "cursor") || !strings.Contains(stderr, "overrides") {
		t.Errorf("expected warning 'user tool \"cursor\" overrides built-in tool'\nstderr:\n%s", stderr)
	}
}

func TestE2E_TOMLFieldMappingCompleteness(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	t.Setenv("E2E_MY_TOKEN", "tokval")

	codexDir := filepath.Join(home, "Library", "Application Support", "Codex")
	if err := os.MkdirAll(codexDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	codexToml := `
[mcp_servers.full-server]
command = "my-binary"
args = ["serve", "--port", "8080"]
url = "https://api.example.com"
bearer_token_env_var = "E2E_MY_TOKEN"
http_headers = { X-API-Key = "key123" }
env = { DEBUG = "1" }
`
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(codexToml), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}

	if !strings.Contains(out, "full-server") {
		t.Error("expected full-server in output")
	}

	findings := parseJSONFindings(t, out)
	found := false
	for _, f := range findings {
		if server, ok := f["server"].(string); ok && server == "full-server" {
			found = true
		}
	}
	if !found {
		t.Error("expected finding for full-server with all fields mapped")
	}
}

func TestE2E_RegressionBuiltinToolsStillWork(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		"Library/Application Support/Claude/claude_desktop_config.json": `{
			"mcpServers": {
				"test-srv": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]}
			}
		}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}
	if !strings.Contains(out, "PASS") {
		t.Errorf("expected PASS for known trusted package\noutput:\n%s", out)
	}
}

func TestE2E_RegressionVersionWorks(t *testing.T) {
	bin := buildBinary(t)
	home := os.Getenv("HOME")
	out, _, code := runMCPAudit(t, bin, home, "version")
	if code != 0 {
		t.Fatalf("expected exit 0 for version, got %d\n%s", code, out)
	}
	if !strings.Contains(out, "mcp-audit") {
		t.Errorf("expected version string\noutput:\n%s", out)
	}
}

func TestE2E_RegressionScanDryRun(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		"Library/Application Support/Claude/claude_desktop_config.json": `{
			"mcpServers": {}
		}`,
	})

	_, _, code := runMCPAudit(t, bin, home, "scan", "--dry-run")
	if code == 2 {
		t.Errorf("scan --dry-run exited with error code 2")
	}
}

func TestE2E_RegressionJSONOutput(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		"Library/Application Support/Claude/claude_desktop_config.json": `{
			"mcpServers": {
				"test-srv": {"command": "npx", "args": ["-y", "some-pkg"]}
			}
		}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}
	if !strings.Contains(out, `"severity"`) {
		t.Error("expected 'severity' field in JSON output")
	}
	if !strings.Contains(out, `"server"`) {
		t.Error("expected 'server' field in JSON output")
	}
}

func TestE2E_RegressionTOMLNoCrashOnNoCodexDir(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		"Library/Application Support/Claude/claude_desktop_config.json": `{
			"mcpServers": {
				"test-srv": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]}
			}
		}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0 with no Codex dir, got %d\n%s", code, out)
	}
	if !strings.Contains(out, "test-srv") {
		t.Error("expected test-srv discovered even without Codex dir")
	}
}

func TestE2E_RegressionSARIFOutputWorks(t *testing.T) {
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

func TestE2E_TildePathExpansion(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		".tilde-tool/mcp.json": `{
			"mcpServers": {
				"tilde-server": {"command": "npx", "args": ["-y", "tilde-pkg"]}
			}
		}`,
	})

	writeToolsJSON(t, home, []map[string]any{
		{
			"name":       "tilde-tool",
			"format":     "json",
			"server_key": "mcpServers",
			"paths":      []string{"~/.tilde-tool/mcp.json"},
		},
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}

	if !strings.Contains(out, "tilde-server") {
		t.Error("expected tilde-server found via tilde path expansion")
	}
}

func TestE2E_EmptyToolsArray(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		"Library/Application Support/Claude/claude_desktop_config.json": `{
			"mcpServers": {
				"claude-server": {"command": "npx", "args": ["-y", "@scope/claude-pkg"]}
			}
		}`,
	})
	writeToolsJSON(t, home, []map[string]any{})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0 with empty tools array, got %d\n%s", code, out)
	}
	if !strings.Contains(out, "claude-server") {
		t.Error("expected built-in claude-server with empty user tools")
	}
}

func TestE2E_UserToolWithoutFormatDefaultsToJSON(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		".no-format-tool/mcp.json": `{
			"mcpServers": {
				"no-format-server": {"command": "npx", "args": ["-y", "no-format-pkg"]}
			}
		}`,
	})

	writeToolsJSON(t, home, []map[string]any{
		{
			"name":       "no-format-tool",
			"server_key": "mcpServers",
			"paths":      []string{filepath.Join(home, ".no-format-tool", "mcp.json")},
		},
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}
	if !strings.Contains(out, "no-format-server") {
		t.Error("expected no-format-server discovered with default JSON format")
	}
}

func TestE2E_ProbeStillDiscoversCodexServers(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	codexDir := filepath.Join(home, "Library", "Application Support", "Codex")
	if err := os.MkdirAll(codexDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	codexToml := `
[mcp_servers.probe-codex-server]
url = "http://127.0.0.1:19999"
`
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(codexToml), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	out, _, code := runMCPAudit(t, bin, home, "probe", "--dry-run", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}
	if !strings.Contains(out, "probe-codex-server") {
		t.Error("expected probe-codex-server in probe dry-run output")
	}
}

func TestE2E_TOMLUnknownFormatFallsBack(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	unknownToolDir := filepath.Join(home, ".unknown-format-tool")
	if err := os.MkdirAll(unknownToolDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(unknownToolDir, "config.toml"), []byte(`
[mcp_servers.s]
command = "echo"
`), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	writeToolsJSON(t, home, []map[string]any{
		{
			"name":       "unknown-fmt-tool",
			"format":     "xml",
			"server_key": "mcpServers",
			"paths":      []string{filepath.Join(unknownToolDir, "config.toml")},
		},
	})

	_, stderr, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code == 2 {
		t.Errorf("expected no crash (exit 2) for unknown format\nstderr:\n%s", stderr)
	}
}

func TestE2E_TOMLSectionWithNeitherCommandNorURL(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	codexDir := filepath.Join(home, "Library", "Application Support", "Codex")
	if err := os.MkdirAll(codexDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	codexToml := `
[mcp_servers.incomplete]
env = { FOO = "bar" }
`
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(codexToml), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0 with incomplete TOML section, got %d\n%s", code, out)
	}

	if strings.Contains(out, "incomplete") {
		t.Error("expected incomplete section without command or url to be skipped")
	}
}

func TestE2E_MultipleServersInTOML(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	codexDir := filepath.Join(home, "Library", "Application Support", "Codex")
	if err := os.MkdirAll(codexDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	codexToml := `
[mcp_servers.first]
command = "npx"
args = ["-y", "@scope/first-pkg"]

[mcp_servers.second]
url = "https://second.example.com/mcp"

[mcp_servers.third]
command = "node"
args = ["server.js"]
`
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(codexToml), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\n%s", code, out)
	}

	for _, name := range []string{"first", "second", "third"} {
		if !strings.Contains(out, name) {
			t.Errorf("expected server %q in output", name)
		}
	}
}

func TestE2E_NonExistentUserToolPath(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeToolsJSON(t, home, []map[string]any{
		{
			"name":       "ghost-tool",
			"format":     "json",
			"server_key": "mcpServers",
			"paths":      []string{"/nonexistent/ghost/mcp.json"},
		},
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0 when user tool path does not exist, got %d\n%s", code, out)
	}
}

func TestE2E_UserToolWithBlankNameSkipped(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeToolsJSON(t, home, []map[string]any{
		{
			"name":       "",
			"format":     "json",
			"server_key": "mcpServers",
			"paths":      []string{"/dev/null"},
		},
	})

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0 with blank-name user tool, got %d\n%s", code, out)
	}
}

func TestE2E_RegressionTableOutputWorks(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()

	writeFiles(t, home, map[string]string{
		"Library/Application Support/Claude/claude_desktop_config.json": `{
			"mcpServers": {
				"tbl-srv": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]}
			}
		}`,
	})

	out, _, code := runMCPAudit(t, bin, home, "static")
	if code != 0 {
		t.Fatalf("expected exit 0 for table output, got %d\n%s", code, out)
	}
	if !strings.Contains(out, "PASS") {
		t.Error("expected PASS in table output")
	}
}
