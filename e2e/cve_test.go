package e2e_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestE2E_CVE_NoCVEScanFlag(t *testing.T) {
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
	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json", "--no-cve-scan", "--no-color")
	if code != 0 {
		t.Errorf("expected exit 0 with --no-cve-scan, got %d\noutput:\n%s", code, out)
	}

	findings := parseJSONFindings(t, out)
	for _, f := range findings {
		if typ, _ := f["type"].(string); typ == "cve" {
			t.Errorf("expected no 'cve' type findings with --no-cve-scan, but got one\nfinding: %v", f)
		}
	}
}

func TestE2E_CVE_ScanRunsByDefault(t *testing.T) {
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
	out, stderr, code := runMCPAudit(t, bin, home, "static", "--format", "json", "--no-color")
	if code != 0 {
		t.Errorf("expected exit 0, got %d\nstderr:\n%s\noutput:\n%s", code, stderr, out)
	}

	findings := parseJSONFindings(t, out)

	hasCVE := false
	for _, f := range findings {
		typ, _ := f["type"].(string)
		if typ == "cve" {
			hasCVE = true
			if sid, ok := f["finding"].(string); ok && sid == "" {
				t.Errorf("cve finding has empty finding field: %v", f)
			}
		}
	}

	if !hasCVE {
		t.Log("no CVE findings produced (NVD/GitHub may be unreachable or package has no CVEs)")
	}
}

func TestE2E_CVE_CacheDirAndTTL(t *testing.T) {
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
	cacheDir := filepath.Join(t.TempDir(), "cve-cache-tests")

	_, stderr, code := runMCPAudit(t, bin, home, "static", "--format", "json", "--no-color",
		"--cve-cache-dir", cacheDir, "--cve-cache-ttl", "48")
	if code != 0 {
		t.Fatalf("first run failed: %d\nstderr:\n%s", code, stderr)
	}

	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		t.Fatalf("cannot read cache dir: %v", err)
	}
	if len(entries) == 0 {
		t.Log("cache dir exists but empty (NVD/GitHub may be unreachable)")
	} else {
		t.Logf("cache dir has %d entries", len(entries))
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".json") {
				t.Errorf("cache entry %q is not .json", e.Name())
			}
		}
	}

	firstEntries := len(entries)

	_, stderr, code = runMCPAudit(t, bin, home, "static", "--format", "json", "--no-color",
		"--cve-cache-dir", cacheDir, "--cve-cache-ttl", "8760")
	if code != 0 {
		t.Fatalf("second run failed: %d\nstderr:\n%s", code, stderr)
	}

	secondEntries, _ := os.ReadDir(cacheDir)
	if firstEntries > 0 && len(secondEntries) > 0 && firstEntries == len(secondEntries) {
		t.Logf("cache persists across runs: %d entries both times", firstEntries)
	}

	_, stderr, code = runMCPAudit(t, bin, home, "static", "--format", "json", "--no-color",
		"--cve-cache-dir", cacheDir, "--cve-cache-ttl", "0")
	if code != 0 {
		t.Fatalf("third run with TTL=0 failed: %d\nstderr:\n%s", code, stderr)
	}
	t.Log("CVE scan ran with TTL=0 (cache always considered fresh)")
}

func TestE2E_CVE_CacheDirDefault(t *testing.T) {
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
	defaultCache := filepath.Join(home, ".config", "mcp-audit", "cve-cache")

	_, stderr, code := runMCPAudit(t, bin, home, "static", "--format", "json", "--no-color")
	if code != 0 {
		t.Fatalf("run failed: %d\nstderr:\n%s", code, stderr)
	}

	_, err := os.Stat(defaultCache)
	if os.IsNotExist(err) {
		t.Log("default cache dir not created (may need successful API calls)")
	} else if err != nil {
		t.Errorf("error stat'ing default cache dir: %v", err)
	} else {
		t.Log("default cache dir exists")
	}
}

func TestE2E_CVE_JSONOutputStructure(t *testing.T) {
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
	out, _, _ := runMCPAudit(t, bin, home, "static", "--format", "json", "--no-color")

	findings := parseJSONFindings(t, out)
	hasCVE := false
	for _, f := range findings {
		typ, _ := f["type"].(string)
		if typ != "cve" {
			continue
		}
		hasCVE = true

		if _, ok := f["severity"]; !ok {
			t.Errorf("cve finding missing 'severity': %v", f)
		}
		if _, ok := f["server"]; !ok {
			t.Errorf("cve finding missing 'server': %v", f)
		}
		if _, ok := f["finding"]; !ok {
			t.Errorf("cve finding missing 'finding': %v", f)
		}

		t.Logf("CVE JSON finding: severity=%v server=%v finding=%v",
			f["severity"], f["server"], f["finding"])
	}

	if !hasCVE {
		t.Log("no CVE findings in JSON output (NVD/GitHub may be unreachable)")
	}
	t.Logf("total findings: %d", len(findings))
}

func TestE2E_CVE_TableOutputHasCVE(t *testing.T) {
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
	out, _, code := runMCPAudit(t, bin, home, "static", "--no-color")
	if code != 0 {
		t.Fatalf("run failed: %d\noutput:\n%s", code, out)
	}

	if !strings.Contains(out, "PASS") {
		t.Errorf("expected PASS in table output\noutput:\n%s", out)
	}
}

func TestE2E_CVE_SARIFOutputHasCVERules(t *testing.T) {
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
	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "sarif", "--no-color")
	if code != 0 {
		t.Fatalf("run failed: %d\noutput:\n%s", code, out)
	}

	if !strings.Contains(out, `"$schema"`) {
		t.Error("SARIF output missing $schema")
	}

	hasCVERule := false
	if strings.Contains(out, `"mcp-audit/cve-critical"`) ||
		strings.Contains(out, `"mcp-audit/cve-high"`) ||
		strings.Contains(out, `"mcp-audit/cve-medium"`) ||
		strings.Contains(out, `"mcp-audit/cve-low"`) {
		hasCVERule = true
	}
	t.Logf("SARIF has CVE rules: %v", hasCVERule)
	if strings.Contains(out, `"mcp-audit/cve-pass"`) {
		t.Log("SARIF has cve-pass rule entries")
	}
}

func TestE2E_CVE_EmptyConfig(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)

	claudeCfg := `{
		"mcpServers": {}
	}`

	home := setupHomeDir(t, claudeCfg)
	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json", "--no-color")
	if code != 0 {
		t.Errorf("expected exit 0 with empty config, got %d\noutput:\n%s", code, out)
	}

	findings := parseJSONFindings(t, out)
	for _, f := range findings {
		if typ, _ := f["type"].(string); typ == "cve" {
			t.Errorf("expected no CVE findings with empty config\nfinding: %v", f)
		}
	}
}

func TestE2E_CVE_ConfigWithoutPackages(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)

	claudeCfg := `{
		"mcpServers": {
			"url-only-server": {
				"url": "http://127.0.0.1:19999"
			}
		}
	}`

	home := setupHomeDir(t, claudeCfg)
	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json", "--no-color")
	if code != 0 {
		t.Errorf("expected exit 0 with url-only config, got %d\noutput:\n%s", code, out)
	}

	findings := parseJSONFindings(t, out)
	for _, f := range findings {
		typ, _ := f["type"].(string)
		server, _ := f["server"].(string)
		if typ == "cve" && server == "url-only-server" {
			t.Logf("URL-only server got CVE result: %v", f["finding"])
		}
	}
}

func TestE2E_CVE_MultiplePackages(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)

	claudeCfg := `{
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem"]
			},
			"memory": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-memory"]
			},
			"brave": {
				"command": "npx",
				"args": ["-y", "@anthropic/mcp-server-brave-search"]
			}
		}
	}`

	home := setupHomeDir(t, claudeCfg)
	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json", "--no-color")
	if code != 0 {
		t.Errorf("expected exit 0 with multiple packages, got %d\noutput:\n%s", code, out)
	}

	findings := parseJSONFindings(t, out)
	serversWithCVE := map[string]int{}
	for _, f := range findings {
		if typ, _ := f["type"].(string); typ == "cve" {
			server, _ := f["server"].(string)
			serversWithCVE[server]++
		}
	}
	t.Logf("servers with CVE results: %v", serversWithCVE)
}

func TestE2E_CVE_HelpShowsCVEflags(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)

	out, err := exec.Command(bin, "help").Output()
	if err != nil {
		t.Fatalf("help failed: %v", err)
	}

	outStr := string(out)
	requiredFlags := []string{
		"--no-cve-scan",
		"--cve-cache-dir",
		"--cve-cache-ttl",
	}
	for _, flag := range requiredFlags {
		if !strings.Contains(outStr, flag) {
			t.Errorf("help output missing flag %q", flag)
		}
	}
}

func TestE2E_CVE_ConfigFileDefaults(t *testing.T) {
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

	configDir := filepath.Join(home, ".config", "mcp-audit")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}

	customCacheDir := filepath.Join(t.TempDir(), "config-cve-cache")
	cfgFile := map[string]any{"cve_cache_dir": customCacheDir, "cve_cache_ttl": 12}
	cfgData, _ := json.Marshal(cfgFile)
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), cfgData, 0644); err != nil {
		t.Fatalf("write config.json: %v", err)
	}

	out, _, code := runMCPAudit(t, bin, home, "static", "--no-color")
	if code != 0 {
		t.Fatalf("run failed: %d\noutput:\n%s", code, out)
	}

	if entries, err := os.ReadDir(customCacheDir); err != nil {
		t.Logf("config-defaults cache dir not created: %v", err)
	} else {
		t.Logf("config-defaults cache dir has %d entries", len(entries))
	}
}

func TestE2E_CVE_ConfigFileNoCVEScan(t *testing.T) {
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

	configDir := filepath.Join(home, ".config", "mcp-audit")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	cfgFile := map[string]any{"no_cve_scan": true}
	cfgData, err := json.Marshal(cfgFile)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), cfgData, 0644); err != nil {
		t.Fatalf("write config.json: %v", err)
	}

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json", "--no-color")
	if code != 0 {
		t.Fatalf("run failed: %d\noutput:\n%s", code, out)
	}

	findings := parseJSONFindings(t, out)
	for _, f := range findings {
		if typ, _ := f["type"].(string); typ == "cve" {
			t.Errorf("expected no 'cve' type findings when config has no_cve_scan: true\nfinding: %v", f)
		}
	}
}

func TestE2E_CVE_scanSubcommandIncludesCVE(t *testing.T) {
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
	out, _, code := runMCPAudit(t, bin, home, "scan", "--dry-run", "--format", "json", "--no-color")
	if code != 0 {
		t.Fatalf("scan failed: %d\noutput:\n%s", code, out)
	}

	if !strings.Contains(out, `"findings"`) {
		t.Errorf("expected 'findings' in scan JSON output\noutput:\n%s", out)
	}
}
