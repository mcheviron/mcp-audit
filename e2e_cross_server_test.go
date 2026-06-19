package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newMCPMockWithTools(t *testing.T, serverName string, tools []map[string]any) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok"))
			return
		}

		var req struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      int             `json:"id"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var result json.RawMessage
		switch req.Method {
		case "initialize":
			result = json.RawMessage(fmt.Sprintf(`{"protocolVersion":"2024-11-05","capabilities":{"tools":{"listChanged":true}},"serverInfo":{"name":%q,"version":"1.0"}}`, serverName))
		case "tools/list":
			toolBytes, _ := json.Marshal(map[string]any{"tools": tools})
			result = json.RawMessage(toolBytes)
		case "tools/call":
			result = json.RawMessage(`{"content":[{"type":"text","text":"ok"}],"isError":false}`)
		default:
			result = json.RawMessage(`{}`)
		}

		resp := map[string]any{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"result":  result,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))

	return srv
}

func setupMultiServerConfig(t *testing.T, servers map[string]string) string {
	t.Helper()
	home := t.TempDir()

	claudeDir := filepath.Join(home, "Library", "Application Support", "Claude")
	if err := os.MkdirAll(claudeDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	mcpServers := make(map[string]any)
	for name, url := range servers {
		mcpServers[name] = map[string]any{"url": url}
	}

	cfg := map[string]any{"mcpServers": mcpServers}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if err := os.WriteFile(
		filepath.Join(claudeDir, "claude_desktop_config.json"),
		data, 0644,
	); err != nil {
		t.Fatalf("write config: %v", err)
	}

	return home
}

func parseJSONFindings(t *testing.T, out string) []map[string]any {
	t.Helper()
	var wrapper struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &wrapper); err != nil {
		t.Fatalf("json parse failed: %v\noutput:\n%s", err, out)
	}
	return wrapper.Findings
}

func TestE2E_CrossServer_GraphBuiltFromToolSchemas_NoEdge(t *testing.T) {
	bin := buildBinary(t)

	srvA := newMCPMockWithTools(t, "text-server", []map[string]any{
		{
			"name":        "get_text",
			"description": "return text content",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"key": map[string]any{"type": "string", "description": "key to look up"},
				},
			},
		},
	})
	defer srvA.Close()

	srvB := newMCPMockWithTools(t, "url-server", []map[string]any{
		{
			"name":        "fetch_url",
			"description": "fetch content from a URL",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"url": map[string]any{"type": "string", "description": "URL to fetch"},
				},
			},
		},
	})
	defer srvB.Close()

	home := setupMultiServerConfig(t, map[string]string{
		"text-server": srvA.URL,
		"url-server":  srvB.URL,
	})

	out, _, _ := runMCPAudit(t, bin, home, "probe",
		"--format", "json", "--concurrency", "1", "--timeout", "10",
		"--targets", "http://127.0.0.1:1")

	results := parseJSONFindings(t, out)

	for _, r := range results {
		tp, _ := r["type"].(string)
		finding, _ := r["finding"].(string)
		if tp == "cross-server" && strings.Contains(finding, "data exfiltration chain") {
			t.Errorf("unexpected chain: text output should not match url input\ngot: %s", finding)
		}
	}
}

func TestE2E_CrossServer_FilesystemToNetworkChain(t *testing.T) {
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
		"--targets", "http://127.0.0.1:1")

	results := parseJSONFindings(t, out)

	foundChain := false
	for _, r := range results {
		tp, _ := r["type"].(string)
		finding, _ := r["finding"].(string)
		sev, _ := r["severity"].(string)
		if tp == "cross-server" && strings.Contains(finding, "potential data exfiltration chain") {
			foundChain = true
			if sev != "MEDIUM" {
				t.Errorf("expected MEDIUM severity, got %s", sev)
			}
			t.Logf("chain found: %s", finding)
		}
	}

	if !foundChain {
		t.Error("expected MEDIUM 'potential data exfiltration chain' finding")
	}
}

func TestE2E_CrossServer_NoChainSafeConfig(t *testing.T) {
	bin := buildBinary(t)

	echoServer := newMCPMockWithTools(t, "echo-server", []map[string]any{
		{
			"name":        "echo",
			"description": "echo back the input text",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"text": map[string]any{"type": "string"},
				},
			},
		},
	})
	defer echoServer.Close()

	calcServer := newMCPMockWithTools(t, "calc-server", []map[string]any{
		{
			"name":        "add",
			"description": "add two numbers",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"a": map[string]any{"type": "number"},
					"b": map[string]any{"type": "number"},
				},
			},
		},
	})
	defer calcServer.Close()

	home := setupMultiServerConfig(t, map[string]string{
		"echo-server": echoServer.URL,
		"calc-server": calcServer.URL,
	})

	out, _, _ := runMCPAudit(t, bin, home, "probe",
		"--format", "json", "--concurrency", "1", "--timeout", "10",
		"--targets", "http://127.0.0.1:1")

	results := parseJSONFindings(t, out)

	for _, r := range results {
		tp, _ := r["type"].(string)
		finding, _ := r["finding"].(string)
		if tp == "cross-server" && strings.Contains(finding, "potential data exfiltration chain") {
			t.Errorf("unexpected chain in safe config: %s", finding)
		}
	}
}

func TestE2E_CrossServer_NoChainReadonlyMiddle(t *testing.T) {
	bin := buildBinary(t)

	readonlyServer := newMCPMockWithTools(t, "readonly-server", []map[string]any{
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
	defer readonlyServer.Close()

	formatServer := newMCPMockWithTools(t, "format-server", []map[string]any{
		{
			"name":        "format_text",
			"description": "format text with a template",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"template": map[string]any{"type": "string"},
				},
			},
		},
	})
	defer formatServer.Close()

	home := setupMultiServerConfig(t, map[string]string{
		"readonly-server": readonlyServer.URL,
		"format-server":   formatServer.URL,
	})

	out, _, _ := runMCPAudit(t, bin, home, "probe",
		"--format", "json", "--concurrency", "1", "--timeout", "10",
		"--targets", "http://127.0.0.1:1")

	results := parseJSONFindings(t, out)

	for _, r := range results {
		tp, _ := r["type"].(string)
		finding, _ := r["finding"].(string)
		if tp == "cross-server" && strings.Contains(finding, "potential data exfiltration chain") {
			t.Errorf("unexpected chain without network tool: %s", finding)
		}
	}
}

func TestE2E_CrossServer_ConfusedDeputyDetected(t *testing.T) {
	bin := buildBinary(t)

	proxyServer := newMCPMockWithTools(t, "proxy-server", []map[string]any{
		{
			"name":        "url_forwarder",
			"description": "forwards URL requests to internal services",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"url": map[string]any{"type": "string", "description": "URL to forward"},
				},
			},
		},
	})
	defer proxyServer.Close()

	fetchServer := newMCPMockWithTools(t, "fetch-server", []map[string]any{
		{
			"name":        "fetch_url",
			"description": "fetch an external URL",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"url": map[string]any{"type": "string", "description": "URL to fetch"},
				},
			},
		},
	})
	defer fetchServer.Close()

	home := setupMultiServerConfig(t, map[string]string{
		"proxy-server": proxyServer.URL,
		"fetch-server": fetchServer.URL,
	})

	out, _, _ := runMCPAudit(t, bin, home, "probe",
		"--format", "json", "--concurrency", "1", "--timeout", "10",
		"--targets", "http://127.0.0.1:1")

	results := parseJSONFindings(t, out)

	foundDeputy := false
	for _, r := range results {
		tp, _ := r["type"].(string)
		finding, _ := r["finding"].(string)
		server, _ := r["server"].(string)
		sev, _ := r["severity"].(string)
		if tp == "cross-server" && strings.Contains(finding, "potential confused deputy") {
			foundDeputy = true
			if sev != "MEDIUM" {
				t.Errorf("expected MEDIUM severity, got %s", sev)
			}
			if server != "proxy-server" {
				t.Errorf("expected server 'proxy-server', got %q", server)
			}
			t.Logf("confused deputy: %s", finding)
		}
	}

	if !foundDeputy {
		t.Error("expected MEDIUM 'potential confused deputy' finding")
	}
}

func TestE2E_CrossServer_ConfusedDeputyNoForwardingKeywords(t *testing.T) {
	bin := buildBinary(t)

	inputServer := newMCPMockWithTools(t, "input-server", []map[string]any{
		{
			"name":        "validate_url",
			"description": "validate a URL format",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"url": map[string]any{"type": "string", "description": "URL to validate"},
				},
			},
		},
	})
	defer inputServer.Close()

	fetchServer := newMCPMockWithTools(t, "fetch-server", []map[string]any{
		{
			"name":        "fetch_url",
			"description": "fetch an external URL",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"url": map[string]any{"type": "string", "description": "URL to fetch"},
				},
			},
		},
	})
	defer fetchServer.Close()

	home := setupMultiServerConfig(t, map[string]string{
		"input-server": inputServer.URL,
		"fetch-server": fetchServer.URL,
	})

	out, _, _ := runMCPAudit(t, bin, home, "probe",
		"--format", "json", "--concurrency", "1", "--timeout", "10",
		"--targets", "http://127.0.0.1:1")

	results := parseJSONFindings(t, out)

	for _, r := range results {
		tp, _ := r["type"].(string)
		finding, _ := r["finding"].(string)
		if tp == "cross-server" && strings.Contains(finding, "potential confused deputy") {
			t.Errorf("unexpected confused deputy for validate_url: %s", finding)
		}
	}
}
