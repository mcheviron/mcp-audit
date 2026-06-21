package e2e_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "mcp-audit")
	cmd := exec.Command("go", "build", "-o", bin, "../cmd/mcp-audit")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	return bin
}

func setupHomeDir(t *testing.T, claudeConfig string) string {
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

func writeTrustConfig(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "trust.json")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write trust config: %v", err)
	}
	return path
}

func runMCPAudit(t *testing.T, bin, home string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = home
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

func newE2EMockMCPServer(t *testing.T) *httptest.Server {
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
			result = json.RawMessage(`{"protocolVersion":"2024-11-05","capabilities":{"tools":{"listChanged":true}},"serverInfo":{"name":"e2e-mock","version":"1.0"}}`)
		case "tools/list":
			result = json.RawMessage(`{"tools":[{"name":"fetch","description":"Fetch a URL","inputSchema":{"type":"object","properties":{"url":{"type":"string","description":"URL to fetch"}},"required":["url"]}}]}`)
		case "tools/call":
			result = json.RawMessage(`{"content":[{"type":"text","text":"fetched ok"}],"isError":false}`)
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

func TestE2EStaticTrustedPackage(t *testing.T) {
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

func TestE2EStaticTyposquatDetected(t *testing.T) {
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
		t.Errorf("expected exit 0 for typosquat (INFO only), got %d\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "typosquat") {
		t.Errorf("expected typosquat detection in output\noutput:\n%s", out)
	}
}

func TestE2EStaticBlockedPackage(t *testing.T) {
	bin := buildBinary(t)

	claudeCfg := `{
		"mcpServers": {
			"evil": {
				"command": "npx",
				"args": ["-y", "evil-package"]
			}
		}
	}`

	home := setupHomeDir(t, claudeCfg)
	trustCfg := writeTrustConfig(t, t.TempDir(), `{
		"blocked": ["evil-package"]
	}`)

	out, _, code := runMCPAudit(t, bin, home, "static", "--trust-config", trustCfg)
	if code != 1 {
		t.Errorf("expected exit 1 for blocked package (CRITICAL), got %d\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "CRITICAL") {
		t.Errorf("expected CRITICAL for blocked package\noutput:\n%s", out)
	}
}

func TestE2EStaticNoTrustConfig(t *testing.T) {
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
	out, _, code := runMCPAudit(t, bin, home, "static")
	if code != 0 {
		t.Errorf("expected exit 0 without trust config, got %d\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "PASS") {
		t.Errorf("expected 'PASS' in output\noutput:\n%s", out)
	}
}

func TestE2EStaticPerToolScope(t *testing.T) {
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
		"tools": {
			"claude": {
				"trusted": ["@modelcontextprotocol/server-filesystem"]
			}
		}
	}`)

	out, _, code := runMCPAudit(t, bin, home, "static", "--trust-config", trustCfg)
	if code != 0 {
		t.Errorf("expected exit 0 for per-tool trusted, got %d\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "PASS") {
		t.Errorf("expected PASS with per-tool trust scope\noutput:\n%s", out)
	}
}

func TestE2EProbeBasic(t *testing.T) {
	srv := newE2EMockMCPServer(t)
	defer srv.Close()

	bin := buildBinary(t)

	claudeCfg := fmt.Sprintf(`{
		"mcpServers": {
			"test-srv": {
				"url": "%s"
			}
		}
	}`, srv.URL)

	home := setupHomeDir(t, claudeCfg)

	out, _, code := runMCPAudit(t, bin, home, "probe", "--format", "json")
	if code == 2 {
		t.Errorf("probe exited with scan error code 2\noutput:\n%s", out)
	}
	if !strings.Contains(out, `"server"`) && !strings.Contains(out, `"Server"`) {
		t.Errorf("expected JSON output with server field\noutput:\n%s", out)
	}
}

func TestE2EProbeDryRun(t *testing.T) {
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
		t.Errorf("expected exit 0 for dry-run, got %d\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "would probe") {
		t.Errorf("expected 'would probe' in dry-run output\noutput:\n%s", out)
	}
}

func TestE2EProbeOutputFormats(t *testing.T) {
	bin := buildBinary(t)

	claudeCfg := `{
		"mcpServers": {
			"test-srv": {
				"url": "http://127.0.0.1:19999"
			}
		}
	}`

	home := setupHomeDir(t, claudeCfg)

	for _, tc := range []struct {
		format, want string
	}{
		{"json", `"severity"`},
		{"sarif", `"$schema"`},
	} {
		t.Run(tc.format, func(t *testing.T) {
			out, _, code := runMCPAudit(t, bin, home, "probe", "--dry-run", "--format", tc.format)
			if code != 0 {
				t.Errorf("exit %d for format %s\noutput:\n%s", code, tc.format, out)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("expected %q in %s output\noutput:\n%s", tc.want, tc.format, out)
			}
		})
	}
}

func TestE2EProbeBlockHosts(t *testing.T) {
	bin := buildBinary(t)

	claudeCfg := `{
		"mcpServers": {}
	}`

	home := setupHomeDir(t, claudeCfg)
	out, _, code := runMCPAudit(t, bin, home, "probe", "--dry-run", "--block-hosts", "169.254.169.254,metadata.google.internal")
	if code != 0 {
		t.Errorf("expected exit 0, got %d\noutput:\n%s", code, out)
	}
	if strings.Contains(out, "169.254.169.254") || strings.Contains(out, "metadata.google.internal") {
		t.Errorf("blocked hosts should not appear in dry-run output\noutput:\n%s", out)
	}
}

func TestE2EVersion(t *testing.T) {
	bin := buildBinary(t)
	out, _, code := runMCPAudit(t, bin, os.Getenv("HOME"), "version")
	if code != 0 {
		t.Errorf("expected exit 0 for version, got %d\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "mcp-audit dev") {
		t.Errorf("expected version string, got:\n%s", out)
	}
}

func TestE2EScan(t *testing.T) {
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
	_, _, code := runMCPAudit(t, bin, home, "scan", "--dry-run")
	if code == 2 {
		t.Errorf("scan exited with error code 2")
	}
}
