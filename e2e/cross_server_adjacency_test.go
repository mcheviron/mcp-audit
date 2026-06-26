package e2e_test

import (
	"os"
	"strings"
	"testing"
)

func TestE2E_CrossServer_AdjacencyElevatedRisk(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)

	fsServer := newMCPMockWithTools(t, "fs-server", []map[string]any{
		{
			"name":        "read_file",
			"description": "read a file from path",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{"type": "string"},
				},
			},
		},
	})
	defer fsServer.Close()

	netServer := newMCPMockWithTools(t, "net-server", []map[string]any{
		{
			"name":        "download",
			"description": "download from URL",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"url": map[string]any{"type": "string"},
				},
			},
		},
	})
	defer netServer.Close()

	shellServer := newMCPMockWithTools(t, "shell-server", []map[string]any{
		{
			"name":        "exec",
			"description": "execute a command",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"command": map[string]any{"type": "string"},
				},
			},
		},
	})
	defer shellServer.Close()

	home := setupMultiServerConfig(t, map[string]string{
		"fs-server":    fsServer.URL,
		"net-server":   netServer.URL,
		"shell-server": shellServer.URL,
	})

	out, _, _ := runMCPAudit(t, bin, home, "probe",
		"--format", "json", "--concurrency", "1", "--timeout", "10",
		"--targets", "http://127.0.0.1:1")

	results := parseJSONFindings(t, out)

	foundAdjacency := false
	for _, r := range results {
		tp, _ := r["type"].(string)
		finding, _ := r["finding"].(string)
		sev, _ := r["severity"].(string)
		if tp == "cross-server" && strings.Contains(finding, "elevated cross-server risk") {
			foundAdjacency = true
			if sev != "INFO" {
				t.Errorf("expected INFO severity, got %s", sev)
			}
			t.Logf("adjacency: %s", finding)
		}
	}

	if !foundAdjacency {
		t.Error("expected INFO 'elevated cross-server risk' finding")
	}
}

func TestE2E_CrossServer_SingleServerNoAnalysis(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)

	loneServer := newMCPMockWithTools(t, "lonely-server", []map[string]any{
		{
			"name":        "read_file",
			"description": "read a file returning text",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{"type": "string", "description": "path to read"},
				},
			},
		},
	})
	defer loneServer.Close()

	home := setupMultiServerConfig(t, map[string]string{
		"lonely-server": loneServer.URL,
	})

	out, _, _ := runMCPAudit(t, bin, home, "probe",
		"--format", "json", "--concurrency", "1", "--timeout", "10",
		"--targets", "http://127.0.0.1:1")

	results := parseJSONFindings(t, out)

	for _, r := range results {
		tp, _ := r["type"].(string)
		finding, _ := r["finding"].(string)
		if tp == "cross-server" {
			t.Errorf("unexpected cross-server finding for single server: %s", finding)
		}
	}
	t.Log("OK: no cross-server findings for single server")
}

func TestE2E_CrossServer_NoCrossServerAnalysisFlag(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)

	fsServer := newMCPMockWithTools(t, "fs-server", []map[string]any{
		{
			"name":        "read_file",
			"description": "read a file and return its text content",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{"type": "string", "description": "file path to read"},
				},
			},
		},
	})
	defer fsServer.Close()

	netServer := newMCPMockWithTools(t, "net-server", []map[string]any{
		{
			"name":        "download",
			"description": "download content from a URL",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"url": map[string]any{"type": "string", "description": "target URL"},
				},
			},
		},
	})
	defer netServer.Close()

	home := setupMultiServerConfig(t, map[string]string{
		"fs-server":  fsServer.URL,
		"net-server": netServer.URL,
	})

	out, _, _ := runMCPAudit(t, bin, home, "probe",
		"--format", "json", "--concurrency", "1", "--timeout", "10",
		"--targets", "http://127.0.0.1:1",
		"--no-cross-server-analysis")

	results := parseJSONFindings(t, out)

	for _, r := range results {
		tp, _ := r["type"].(string)
		finding, _ := r["finding"].(string)
		if tp == "cross-server" {
			t.Errorf("unexpected cross-server finding with --no-cross-server-analysis: %s", finding)
		}
	}
	t.Log("OK: --no-cross-server-analysis suppresses cross-server findings")
}

func TestE2E_CrossServer_InvalidSchemaSafe(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)

	badServer := newMCPMockWithTools(t, "bad-server", []map[string]any{
		{
			"name":        "broken_tool",
			"description": "tool with no inputSchema",
		},
	})
	defer badServer.Close()

	goodServer := newMCPMockWithTools(t, "good-server", []map[string]any{
		{
			"name":        "fetch_url",
			"description": "fetch a URL",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"url": map[string]any{"type": "string", "description": "URL to fetch"},
				},
			},
		},
	})
	defer goodServer.Close()

	home := setupMultiServerConfig(t, map[string]string{
		"bad-server":  badServer.URL,
		"good-server": goodServer.URL,
	})

	out, _, _ := runMCPAudit(t, bin, home, "probe",
		"--format", "json", "--concurrency", "1", "--timeout", "10",
		"--targets", "http://127.0.0.1:1")

	results := parseJSONFindings(t, out)

	for _, r := range results {
		tp, _ := r["type"].(string)
		finding, _ := r["finding"].(string)
		if tp == "cross-server" && strings.Contains(finding, "potential data exfiltration chain") {
			t.Errorf("unexpected chain with broken tool schema: %s", finding)
		}
	}
}

func TestE2E_CrossServer_RegressionStaticStillWorks(t *testing.T) {
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
	trustCfg := writeTrustConfig(t, t.TempDir(), `{
			"trusted": ["@modelcontextprotocol/server-filesystem"]
		}`)

	out, _, code := runMCPAudit(t, bin, home, "static", "--trust-config", trustCfg)
	if code != 0 {
		t.Errorf("static regression: expected exit 0, got %d\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "PASS") {
		t.Errorf("static regression: expected PASS in output\noutput:\n%s", out)
	}
}

func TestE2E_CrossServer_RegressionProbeDryRunStillWorks(t *testing.T) {
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
		t.Errorf("probe dry-run regression: expected exit 0, got %d\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "would probe") {
		t.Errorf("probe dry-run regression: expected 'would probe'\noutput:\n%s", out)
	}
}

func TestE2E_CrossServer_RegressionVersionStillWorks(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)
	out, _, code := runMCPAudit(t, bin, os.Getenv("HOME"), "version")
	if code != 0 {
		t.Errorf("version regression: expected exit 0, got %d\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "mcp-audit dev") {
		t.Errorf("version regression: expected version string\noutput:\n%s", out)
	}
}

func TestE2E_CrossServer_ToolDescriptionAnalysisWithKeywords(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)

	proxyServer := newMCPMockWithTools(t, "proxy-server", []map[string]any{
		{
			"name":        "fetch",
			"description": "download and forward content from URLs",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"url": map[string]any{"type": "string", "description": "URL to fetch"},
				},
			},
		},
	})
	defer proxyServer.Close()

	otherServer := newMCPMockWithTools(t, "other-server", []map[string]any{
		{
			"name":        "fetch_url",
			"description": "fetch a URL",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"url": map[string]any{"type": "string", "description": "URL to fetch"},
				},
			},
		},
	})
	defer otherServer.Close()

	home := setupMultiServerConfig(t, map[string]string{
		"proxy-server": proxyServer.URL,
		"other-server": otherServer.URL,
	})

	out, _, _ := runMCPAudit(t, bin, home, "probe",
		"--format", "json", "--concurrency", "1", "--timeout", "10",
		"--targets", "http://127.0.0.1:1")

	results := parseJSONFindings(t, out)

	foundDeputy := false
	for _, r := range results {
		tp, _ := r["type"].(string)
		finding, _ := r["finding"].(string)
		if tp == "cross-server" && strings.Contains(finding, "potential confused deputy") && strings.Contains(finding, "fetch") {
			foundDeputy = true
			t.Logf("confused deputy for 'fetch' tool: %s", finding)
		}
	}

	if !foundDeputy {
		t.Error("expected confused deputy for 'fetch' tool with 'download/forward' in description")
	}
}

func TestE2E_CrossServer_ScanSubcommandFlagDefault(t *testing.T) {
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
	trustCfg := writeTrustConfig(t, t.TempDir(), `{
			"trusted": ["@modelcontextprotocol/server-filesystem"]
		}`)

	out, _, code := runMCPAudit(t, bin, home, "scan", "--trust-config", trustCfg)
	if code != 0 {
		t.Errorf("scan regression: expected exit 0, got %d\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "PASS") {
		t.Errorf("scan regression: expected PASS in output\noutput:\n%s", out)
	}
}

func TestE2E_CrossServer_HelpShowsFlag(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)
	out, _, code := runMCPAudit(t, bin, os.Getenv("HOME"), "help")
	if code != 0 {
		t.Errorf("help: expected exit 0, got %d", code)
	}
	if !strings.Contains(out, "no-cross-server-analysis") {
		t.Errorf("help should mention --no-cross-server-analysis flag\noutput:\n%s", out)
	}
}
