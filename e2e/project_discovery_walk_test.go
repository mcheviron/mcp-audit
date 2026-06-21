package e2e_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func setupHomeWithClaudeDesktop(t *testing.T, claudeConfig string) string {
	t.Helper()
	home := t.TempDir()
	claudeDir := filepath.Join(home, "Library", "Application Support", "Claude")
	if err := os.MkdirAll(claudeDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(claudeDir, "claude_desktop_config.json"),
		[]byte(claudeConfig), 0644,
	); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return home
}

func setupCursorGlobal(t *testing.T, home, cursorConfig string) {
	t.Helper()
	cursorDir := filepath.Join(home, ".cursor")
	if err := os.MkdirAll(cursorDir, 0755); err != nil {
		t.Fatalf("mkdir cursor: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(cursorDir, "mcp.json"),
		[]byte(cursorConfig), 0644,
	); err != nil {
		t.Fatalf("write cursor config: %v", err)
	}
}

func setupVSCodeGlobal(t *testing.T, home, vsConfig string) {
	t.Helper()
	vsDir := filepath.Join(home, ".vscode")
	if err := os.MkdirAll(vsDir, 0755); err != nil {
		t.Fatalf("mkdir vscode: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(vsDir, "mcp.json"),
		[]byte(vsConfig), 0644,
	); err != nil {
		t.Fatalf("write vscode config: %v", err)
	}
}

func writeProjectConfig(t *testing.T, dir string, content string) error {
	t.Helper()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, ".mcp.json"), []byte(content), 0644)
}

func parseJSONOutput(t *testing.T, out string) []map[string]any {
	t.Helper()
	var wrapper struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &wrapper); err != nil {
		t.Fatalf("json parse failed: %v\noutput:\n%s", err, out)
	}
	return wrapper.Findings
}

func runMCPAuditWithCwd(t *testing.T, bin, home, cwd string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = cwd
	cmd.Env = append(os.Environ(), "HOME="+home)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("run failed: %v\nstderr: %s", err, stderr.String())
		}
	}

	return stdout.String(), stderr.String(), code
}

func TestE2EProjectDiscoveryConfigAtCwd(t *testing.T) {
	bin := buildBinary(t)

	home := setupHomeWithClaudeDesktop(t, `{"mcpServers":{}}`)

	cwd := t.TempDir()
	projectCfg := `{"mcpServers":{"my-srv":{"command":"echo","args":["hello"]}}}`
	if err := writeProjectConfig(t, cwd, projectCfg); err != nil {
		t.Fatalf("write project config: %v", err)
	}

	out, _, code := runMCPAuditWithCwd(t, bin, home, cwd, "static", "--format", "json")
	if code != 0 {
		t.Errorf("expected exit 0, got %d\noutput:\n%s", code, out)
	}

	findings := parseJSONOutput(t, out)
	found := false
	for _, f := range findings {
		server, _ := f["server"].(string)
		sc, _ := f["scope"].(string)
		if server == "my-srv" && sc == "project" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'my-srv' with scope 'project' in findings\noutput:\n%s", out)
	}
}

func TestE2EProjectDiscoveryConfigOneLevelUp(t *testing.T) {
	bin := buildBinary(t)

	home := setupHomeWithClaudeDesktop(t, `{"mcpServers":{}}`)

	projectDir := t.TempDir()
	projectCfg := `{"mcpServers":{"deep-srv":{"command":"node","args":["server.js"]}}}`
	if err := writeProjectConfig(t, projectDir, projectCfg); err != nil {
		t.Fatalf("write project config: %v", err)
	}

	subDir := filepath.Join(projectDir, "src", "lib")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("mkdir subdir: %v", err)
	}

	out, _, code := runMCPAuditWithCwd(t, bin, home, subDir, "static", "--format", "json")
	if code != 0 {
		t.Errorf("expected exit 0, got %d\noutput:\n%s", code, out)
	}

	findings := parseJSONOutput(t, out)
	found := false
	for _, f := range findings {
		server, _ := f["server"].(string)
		sc, _ := f["scope"].(string)
		if server == "deep-srv" && sc == "project" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'deep-srv' with scope 'project' discovered from parent dir\noutput:\n%s", out)
	}
}

func TestE2EProjectDiscoveryNoProjectConfigFallsBackToGlobal(t *testing.T) {
	bin := buildBinary(t)

	home := setupHomeWithClaudeDesktop(t, `{"mcpServers":{"global-srv":{"command":"echo","args":["global"]}}}`)

	cwd := t.TempDir()

	out, _, code := runMCPAuditWithCwd(t, bin, home, cwd, "static", "--format", "json")
	if code != 0 {
		t.Errorf("expected exit 0, got %d\noutput:\n%s", code, out)
	}

	foundGlobal := false
	findings := parseJSONOutput(t, out)
	for _, f := range findings {
		server, _ := f["server"].(string)
		sc, _ := f["scope"].(string)
		if server == "global-srv" && sc == "global" {
			foundGlobal = true
		}
	}
	if !foundGlobal {
		t.Errorf("expected 'global-srv' with scope 'global' when no project config exists\noutput:\n%s", out)
	}
}

func TestE2EProjectDiscoveryNoProjectFlag(t *testing.T) {
	bin := buildBinary(t)

	home := setupHomeWithClaudeDesktop(t, `{"mcpServers":{"global-srv":{"command":"echo","args":["global"]}}}`)

	cwd := t.TempDir()
	projectCfg := `{"mcpServers":{"project-srv":{"command":"echo","args":["project"]}}}`
	if err := writeProjectConfig(t, cwd, projectCfg); err != nil {
		t.Fatalf("write project config: %v", err)
	}

	out, _, code := runMCPAuditWithCwd(t, bin, home, cwd, "static", "--format", "json", "--no-project-config")
	if code != 0 {
		t.Errorf("expected exit 0, got %d\noutput:\n%s", code, out)
	}

	findings := parseJSONOutput(t, out)
	foundGlobal := false
	hasProjectScope := false
	for _, f := range findings {
		server, _ := f["server"].(string)
		sc, _ := f["scope"].(string)
		if server == "global-srv" {
			foundGlobal = true
		}
		if sc == "project" {
			hasProjectScope = true
		}
	}
	if hasProjectScope {
		t.Errorf("no server should have scope 'project' with --no-project-config\noutput:\n%s", out)
	}
	if !foundGlobal {
		t.Errorf("global-srv should still appear with --no-project-config\noutput:\n%s", out)
	}
}

func TestE2EProjectDiscoveryProjectDirFlag(t *testing.T) {
	bin := buildBinary(t)

	home := setupHomeWithClaudeDesktop(t, `{"mcpServers":{}}`)

	actualCwd := t.TempDir()
	projectDir := filepath.Join(actualCwd, "my-project")
	projectCfg := `{"mcpServers":{"explicit-srv":{"command":"echo","args":["explicit"]}}}`
	if err := writeProjectConfig(t, projectDir, projectCfg); err != nil {
		t.Fatalf("write project config: %v", err)
	}

	out, _, code := runMCPAuditWithCwd(t, bin, home, actualCwd, "static", "--format", "json", "--project-dir", projectDir)
	if code != 0 {
		t.Errorf("expected exit 0, got %d\noutput:\n%s", code, out)
	}

	findings := parseJSONOutput(t, out)
	found := false
	for _, f := range findings {
		server, _ := f["server"].(string)
		sc, _ := f["scope"].(string)
		if server == "explicit-srv" && sc == "project" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'explicit-srv' with scope 'project' via --project-dir\noutput:\n%s", out)
	}
}

func TestE2EProjectDiscoveryNoConfigsFound(t *testing.T) {
	bin := buildBinary(t)

	home := t.TempDir()
	cwd := t.TempDir()

	out, _, code := runMCPAuditWithCwd(t, bin, home, cwd, "static", "--format", "json")
	if code != 0 {
		t.Errorf("expected exit 0 when no configs found, got %d\noutput:\n%s", code, out)
	}

	var wrapper struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &wrapper); err != nil {
		t.Fatalf("json parse: %v", err)
	}
	if len(wrapper.Findings) > 0 {
		t.Errorf("expected 0 findings with no configs, got %d\noutput:\n%s", len(wrapper.Findings), out)
	}
}

func TestE2EProjectDiscoveryCorruptProjectConfig(t *testing.T) {
	bin := buildBinary(t)

	home := setupHomeWithClaudeDesktop(t, `{"mcpServers":{"ok-srv":{"command":"echo","args":["ok"]}}}`)

	cwd := t.TempDir()
	if err := writeProjectConfig(t, cwd, `not valid json at all`); err != nil {
		t.Fatalf("write project config: %v", err)
	}

	out, _, code := runMCPAuditWithCwd(t, bin, home, cwd, "static", "--format", "json")
	if code != 0 {
		t.Errorf("expected exit 0 with corrupt project config, got %d\noutput:\n%s", code, out)
	}

	findings := parseJSONOutput(t, out)
	foundOk := false
	foundError := false
	for _, f := range findings {
		cfgPath, _ := f["config_path"].(string)
		finding, _ := f["finding"].(string)
		if strings.Contains(cfgPath, ".mcp.json") && strings.Contains(finding, "parse error") {
			foundError = true
		}
		if server, _ := f["server"].(string); server == "ok-srv" {
			foundOk = true
		}
	}
	if !foundError {
		t.Errorf("expected parse error for corrupt project config\noutput:\n%s", out)
	}
	if !foundOk {
		t.Errorf("expected global ok-srv to still appear despite corrupt project config\noutput:\n%s", out)
	}
}

func TestE2EProjectDiscoveryAllToolsConfigured(t *testing.T) {
	bin := buildBinary(t)

	home := setupHomeWithClaudeDesktop(t, `{"mcpServers":{"a":{"command":"echo","args":["a"]}}}`)
	setupCursorGlobal(t, home, `{"mcpServers":{"b":{"command":"echo","args":["b"]}}}`)
	setupVSCodeGlobal(t, home, `{"mcpServers":{"c":{"command":"echo","args":["c"]}}}`)

	cwd := t.TempDir()

	out, _, code := runMCPAuditWithCwd(t, bin, home, cwd, "static", "--format", "json")
	if code != 0 {
		t.Errorf("expected exit 0, got %d\noutput:\n%s", code, out)
	}

	findings := parseJSONOutput(t, out)
	serversFound := map[string]bool{}
	for _, f := range findings {
		server, _ := f["server"].(string)
		serversFound[server] = true
	}
	for _, name := range []string{"a", "b", "c"} {
		if !serversFound[name] {
			t.Errorf("expected server %q from all three tools, missing\noutput:\n%s", name, out)
		}
	}
}
