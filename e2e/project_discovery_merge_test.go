package e2e_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hashicorp/go-set"
)

func TestE2EProjectDiscoveryOverrideGlobalServer(t *testing.T) {
	bin := buildBinary(t)

	home := setupHomeWithClaudeDesktop(t, `{"mcpServers":{"db":{"url":"http://staging-db/mcp"}}}`)

	cwd := t.TempDir()
	projectCfg := `{"mcpServers":{"db":{"url":"http://prod-db/mcp"}}}`
	if err := writeProjectConfig(t, cwd, projectCfg); err != nil {
		t.Fatalf("write project config: %v", err)
	}

	out, _, code := runMCPAuditWithCwd(t, bin, home, cwd, "static", "--format", "json")
	if code != 0 {
		t.Errorf("expected exit 0, got %d\noutput:\n%s", code, out)
	}

	findings := parseJSONOutput(t, out)
	var dbEntries []map[string]any
	for _, f := range findings {
		server, _ := f["server"].(string)
		if server == "db" {
			dbEntries = append(dbEntries, f)
		}
	}
	if len(dbEntries) != 1 {
		t.Errorf("expected exactly 1 'db' entry after merge (project overrides global), got %d\noutput:\n%s", len(dbEntries), out)
		return
	}
	sc, _ := dbEntries[0]["scope"].(string)
	if sc != "project" {
		t.Errorf("expected merged 'db' to have scope 'project', got %q\noutput:\n%s", sc, out)
	}
}

func TestE2EProjectDiscoveryNonConflictingServersMerged(t *testing.T) {
	bin := buildBinary(t)

	home := setupHomeWithClaudeDesktop(t, `{"mcpServers":{"slack":{"url":"http://slack/mcp"}}}`)

	cwd := t.TempDir()
	projectCfg := `{"mcpServers":{"db":{"url":"http://db/mcp"}}}`
	if err := writeProjectConfig(t, cwd, projectCfg); err != nil {
		t.Fatalf("write project config: %v", err)
	}

	out, _, code := runMCPAuditWithCwd(t, bin, home, cwd, "static", "--format", "json")
	if code != 0 {
		t.Errorf("expected exit 0, got %d\noutput:\n%s", code, out)
	}

	findings := parseJSONOutput(t, out)
	servers := map[string]string{}
	for _, f := range findings {
		server, _ := f["server"].(string)
		sc, _ := f["scope"].(string)
		servers[server] = sc
	}
	if servers["db"] != "project" {
		t.Errorf("expected 'db' with scope 'project', got %q\noutput:\n%s", servers["db"], out)
	}
	if servers["slack"] != "global" {
		t.Errorf("expected 'slack' with scope 'global', got %q\noutput:\n%s", servers["slack"], out)
	}
}

func TestE2EProjectDiscoveryGlobalScopeInJSON(t *testing.T) {
	bin := buildBinary(t)

	home := setupHomeWithClaudeDesktop(t, `{"mcpServers":{"global-only":{"command":"echo","args":["hello"]}}}`)

	cwd := t.TempDir()

	out, _, code := runMCPAuditWithCwd(t, bin, home, cwd, "static", "--format", "json")
	if code != 0 {
		t.Errorf("expected exit 0, got %d\noutput:\n%s", code, out)
	}

	findings := parseJSONOutput(t, out)
	found := false
	for _, f := range findings {
		server, _ := f["server"].(string)
		sc, _ := f["scope"].(string)
		cp, _ := f["config_path"].(string)
		if server == "global-only" {
			if sc != "global" {
				t.Errorf("expected scope 'global', got %q", sc)
			}
			if !strings.Contains(cp, "claude_desktop_config.json") {
				t.Errorf("config_path should reference claude_desktop_config.json, got %q", cp)
			}
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'global-only' server in findings\noutput:\n%s", out)
	}
}

func TestE2EProjectDiscoverySameServerNameDifferentTools(t *testing.T) {
	bin := buildBinary(t)

	home := setupHomeWithClaudeDesktop(t, `{"mcpServers":{"db":{"url":"http://claude-db/mcp"}}}`)
	setupCursorGlobal(t, home, `{"mcpServers":{"db":{"url":"http://cursor-db/mcp"}}}`)

	cwd := t.TempDir()

	out, _, code := runMCPAuditWithCwd(t, bin, home, cwd, "static", "--format", "json")
	if code != 0 {
		t.Errorf("expected exit 0, got %d\noutput:\n%s", code, out)
	}

	findings := parseJSONOutput(t, out)
	var dbEntries []map[string]any
	for _, f := range findings {
		server, _ := f["server"].(string)
		if server == "db" {
			dbEntries = append(dbEntries, f)
		}
	}
	if len(dbEntries) < 1 {
		t.Errorf("expected at least 1 'db' entry, got %d\noutput:\n%s", len(dbEntries), out)
	}
	seenTools := set.New[string](0)
	for _, entry := range dbEntries {
		cp, _ := entry["config_path"].(string)
		seenTools.Insert(cp)
	}
	if seenTools.Size() >= 2 {
		t.Logf("both db entries preserved via distinct config_paths: %v", seenTools.Slice())
	}
}

func TestE2EProjectDiscoveryScopeInTableOutput(t *testing.T) {
	bin := buildBinary(t)

	home := setupHomeWithClaudeDesktop(t, `{"mcpServers":{}}`)

	cwd := t.TempDir()
	projectCfg := `{"mcpServers":{"tbl-srv":{"command":"table-test","args":[]}}}`
	if err := writeProjectConfig(t, cwd, projectCfg); err != nil {
		t.Fatalf("write project config: %v", err)
	}

	out, _, code := runMCPAuditWithCwd(t, bin, home, cwd, "static")
	if code != 0 {
		t.Errorf("expected exit 0, got %d\noutput:\n%s", code, out)
	}

	if !strings.Contains(out, "tbl-srv") {
		t.Errorf("expected 'tbl-srv' in table output\noutput:\n%s", out)
	}
	if !strings.Contains(out, "(project)") {
		t.Errorf("expected '(project)' annotation in table output\noutput:\n%s", out)
	}
}

func TestE2EProjectDiscoveryMixedConfigScopeAnnotated(t *testing.T) {
	bin := buildBinary(t)

	home := setupHomeWithClaudeDesktop(t, `{"mcpServers":{"glob":{"command":"global","args":[]}}}`)

	cwd := t.TempDir()
	projectCfg := `{"mcpServers":{"proj":{"command":"project","args":[]}}}`
	if err := writeProjectConfig(t, cwd, projectCfg); err != nil {
		t.Fatalf("write project config: %v", err)
	}

	out, _, code := runMCPAuditWithCwd(t, bin, home, cwd, "static", "--format", "json")
	if code != 0 {
		t.Errorf("expected exit 0, got %d\noutput:\n%s", code, out)
	}

	findings := parseJSONOutput(t, out)
	scopeMap := map[string]string{}
	for _, f := range findings {
		server, _ := f["server"].(string)
		sc, _ := f["scope"].(string)
		scopeMap[server] = sc
	}
	if scopeMap["proj"] != "project" {
		t.Errorf("expected 'proj' scope=project, got %q", scopeMap["proj"])
	}
	if scopeMap["glob"] != "global" {
		t.Errorf("expected 'glob' scope=global, got %q", scopeMap["glob"])
	}
}

func TestE2EProjectDiscoveryRegressionGlobalNothingBroken(t *testing.T) {
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
	trustCfg := writeTrustConfig(t, t.TempDir(), `{
		"trusted": ["@modelcontextprotocol/server-filesystem"]
	}`)

	out, _, code := runMCPAudit(t, bin, home, "static", "--trust-config", trustCfg)
	if code != 0 {
		t.Errorf("expected exit 0 for trusted package, got %d\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "PASS") {
		t.Errorf("expected PASS finding for trusted package\noutput:\n%s", out)
	}
}

func TestE2EProjectDiscoveryJSONOutputHasScopeField(t *testing.T) {
	bin := buildBinary(t)

	home := setupHomeWithClaudeDesktop(t, `{"mcpServers":{"json-srv":{"command":"echo","args":["hi"]}}}`)

	cwd := t.TempDir()
	projectCfg := `{"mcpServers":{"proj-json":{"command":"node","args":["s.js"]}}}`
	if err := writeProjectConfig(t, cwd, projectCfg); err != nil {
		t.Fatalf("write project config: %v", err)
	}

	out, _, code := runMCPAuditWithCwd(t, bin, home, cwd, "static", "--format", "json")
	if code != 0 {
		t.Errorf("expected exit 0, got %d\noutput:\n%s", code, out)
	}

	var wrapper struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &wrapper); err != nil {
		t.Fatalf("json parse: %v", err)
	}
	for i, f := range wrapper.Findings {
		sc, hasScope := f["scope"]
		if !hasScope || sc == nil || sc == "" {
			t.Errorf("finding %d is missing scope field: %v", i, f)
		}
		scope, _ := f["scope"].(string)
		if scope != "project" && scope != "global" {
			t.Errorf("finding %d server=%q has unexpected scope %q", i, f["server"], scope)
		}
	}
}

func TestE2EProjectDiscoveryProbeRespectsProjectScope(t *testing.T) {
	bin := buildBinary(t)

	home := setupHomeWithClaudeDesktop(t, `{"mcpServers":{}}`)

	cwd := t.TempDir()
	projectCfg := `{"mcpServers":{"probe-proj":{"url":"http://127.0.0.1:19999"}}}`
	if err := writeProjectConfig(t, cwd, projectCfg); err != nil {
		t.Fatalf("write project config: %v", err)
	}

	out, _, code := runMCPAuditWithCwd(t, bin, home, cwd, "probe", "--dry-run", "--format", "json")
	if code != 0 {
		t.Errorf("expected exit 0, got %d\noutput:\n%s", code, out)
	}

	if !strings.Contains(out, "probe-proj") {
		t.Errorf("expected 'probe-proj' from project config to appear in probe output\noutput:\n%s", out)
	}
	if !strings.Contains(out, `"scope"`) {
		t.Errorf("expected scope field in probe output\noutput:\n%s", out)
	}
}
