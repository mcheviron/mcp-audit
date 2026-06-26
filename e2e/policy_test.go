package e2e_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mcheviron/mcp-audit/internal/proxy"
)

func writePolicyFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}

func TestE2EPolicyDenyRuleBlocksRequest(t *testing.T) {
	t.Parallel()
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("target server should not be called for denied request")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"should not reach"}]}}`))
	}))
	defer targetServer.Close()

	policyYAML := `
rules:
  - action: deny
    priority: 10
    method: tools/call
    tool: dangerous_tool
    description: "Block dangerous tool"
  - action: allow
    priority: 20
    method: "*"
`
	policyPath := writePolicyFile(t, policyYAML)
	cfg := proxy.Config{
		TargetURL:       targetServer.URL,
		BlockCritical:   false,
		MaxResponseSize: 65536,
		PolicyPath:      policyPath,
	}
	p := proxy.New(cfg)

	handler := p.Handler()
	proxySrv := httptest.NewServer(handler)
	defer proxySrv.Close()

	toolsCallReq := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"dangerous_tool","arguments":{}}}`
	resp, err := http.Post(proxySrv.URL, "application/json", strings.NewReader(toolsCallReq))
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("X-MCP-Audit-Blocked") != "true" {
		t.Fatal("expected X-MCP-Audit-Blocked header for denied request")
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	errObj, ok := result["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error in response, got: %v", result)
	}

	code, _ := errObj["code"].(float64)
	if code != -32001 {
		t.Errorf("expected error code -32001, got %v", code)
	}

	msg, _ := errObj["message"].(string)
	if !strings.Contains(msg, "Denied by policy") {
		t.Errorf("expected 'Denied by policy' in message, got: %q", msg)
	}
}

func TestE2EPolicyAuditRuleForwardsRequest(t *testing.T) {
	t.Parallel()
	targetCalled := false
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetCalled = true
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`))
	}))
	defer targetServer.Close()

	policyYAML := `
rules:
  - action: audit
    priority: 10
    method: tools/call
    tool: safe_tool
    description: "Audit safe tool usage"
  - action: allow
    priority: 20
    method: "*"
`
	policyPath := writePolicyFile(t, policyYAML)
	cfg := proxy.Config{
		TargetURL:       targetServer.URL,
		BlockCritical:   false,
		MaxResponseSize: 65536,
		PolicyPath:      policyPath,
	}
	p := proxy.New(cfg)

	handler := p.Handler()
	proxySrv := httptest.NewServer(handler)
	defer proxySrv.Close()

	toolsCallReq := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe_tool","arguments":{}}}`
	resp, err := http.Post(proxySrv.URL, "application/json", strings.NewReader(toolsCallReq))
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()

	if !targetCalled {
		t.Error("expected target server to be called for audit rule")
	}

	if resp.Header.Get("X-MCP-Audit-Blocked") == "true" {
		t.Error("expected no block header for audit rule")
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if _, ok := result["error"]; ok {
		t.Errorf("expected no error in forwarded response, got: %v", result)
	}

	resultObj, ok := result["result"].(map[string]any)
	if !ok {
		t.Fatalf("expected result in response, got: %v", result)
	}
	content, ok := resultObj["content"].([]any)
	if !ok || len(content) != 1 {
		t.Fatalf("expected content array, got: %v", resultObj)
	}
}

func TestE2EPolicyDefaultDenyBlocksAll(t *testing.T) {
	t.Parallel()
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`))
	}))
	defer targetServer.Close()

	policyYAML := `
rules:
  - action: allow
    priority: 10
    method: tools/list
`
	policyPath := writePolicyFile(t, policyYAML)
	cfg := proxy.Config{
		TargetURL:       targetServer.URL,
		BlockCritical:   false,
		MaxResponseSize: 65536,
		PolicyPath:      policyPath,
		DefaultDeny:     true,
	}
	p := proxy.New(cfg)

	handler := p.Handler()
	proxySrv := httptest.NewServer(handler)
	defer proxySrv.Close()

	// tools/list should be allowed (explicit allow rule)
	listReq := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	resp, err := http.Post(proxySrv.URL, "application/json", strings.NewReader(listReq))
	if err != nil {
		t.Fatalf("proxy list request: %v", err)
	}
	resp.Body.Close()

	if resp.Header.Get("X-MCP-Audit-Blocked") == "true" {
		t.Error("expected tools/list to be allowed with default-deny (has allow rule)")
	}

	// tools/call should be denied (no allow rule for it)
	toolsCallReq := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"some_tool","arguments":{}}}`
	resp2, err := http.Post(proxySrv.URL, "application/json", strings.NewReader(toolsCallReq))
	if err != nil {
		t.Fatalf("proxy call request: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.Header.Get("X-MCP-Audit-Blocked") != "true" {
		t.Fatal("expected X-MCP-Audit-Blocked header for default-deny")
	}

	var result map[string]any
	if err := json.NewDecoder(resp2.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	errObj, ok := result["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error in response, got: %v", result)
	}

	code, _ := errObj["code"].(float64)
	if code != -32001 {
		t.Errorf("expected error code -32001, got %v", code)
	}
}

func TestE2EPolicyAllowRuleForwardsRequest(t *testing.T) {
	t.Parallel()
	targetCalled := false
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetCalled = true
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`))
	}))
	defer targetServer.Close()

	policyYAML := `
rules:
  - action: allow
    priority: 10
    method: tools/call
    tool: safe_tool
`
	policyPath := writePolicyFile(t, policyYAML)
	cfg := proxy.Config{
		TargetURL:       targetServer.URL,
		BlockCritical:   false,
		MaxResponseSize: 65536,
		PolicyPath:      policyPath,
	}
	p := proxy.New(cfg)

	handler := p.Handler()
	proxySrv := httptest.NewServer(handler)
	defer proxySrv.Close()

	toolsCallReq := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe_tool","arguments":{}}}`
	resp, err := http.Post(proxySrv.URL, "application/json", strings.NewReader(toolsCallReq))
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()

	if !targetCalled {
		t.Error("expected target server to be called for allowed request")
	}
}
