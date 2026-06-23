package e2e_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mostafaelataby-cheviron/mcp-audit/internal/proxy"
)

// Scenario: Regex condition
// WHEN a rule has conditions: {params.arguments.url: {op: regex, value: "https?://internal\\.corp"}}
// and the request contains params.arguments.url: "http://internal.corp/api"
// THEN the condition matches
func TestE2EPolicyConditionRegex(t *testing.T) {
	targetCalled := false
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetCalled = true
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`))
	}))
	defer targetServer.Close()

	policyYAML := `
rules:
  - action: deny
    priority: 10
    method: tools/call
    tool: fetch
    description: "Block internal URLs"
    conditions:
      params.arguments.url:
        op: regex
        value: "https?://internal\\.corp"
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

	// URL matching regex should be denied
	internalReq := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch","arguments":{"url":"http://internal.corp/api"}}}`
	resp, err := http.Post(proxySrv.URL, "application/json", strings.NewReader(internalReq))
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("X-MCP-Audit-Blocked") != "true" {
		t.Fatal("expected block for regex matching internal URL")
	}
	if targetCalled {
		t.Fatal("target should not be called when regex condition matches")
	}

	// URL not matching regex should be allowed
	targetCalled = false
	externalReq := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fetch","arguments":{"url":"https://example.com"}}}`
	resp2, err := http.Post(proxySrv.URL, "application/json", strings.NewReader(externalReq))
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.Header.Get("X-MCP-Audit-Blocked") == "true" {
		t.Fatal("expected external URL to NOT be blocked by internal.corp regex")
	}
}

// Scenario: Default allow without flag
// WHEN --default-deny is not set and no rule matches the incoming request
// THEN the request is forwarded normally
func TestE2EPolicyDefaultAllowNoFlag(t *testing.T) {
	targetCalls := 0
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetCalls++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`))
	}))
	defer targetServer.Close()

	// Policy only allows tools/list; tools/call has no allow rule, but no default-deny
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
		DefaultDeny:     false,
	}
	p := proxy.New(cfg)

	handler := p.Handler()
	proxySrv := httptest.NewServer(handler)
	defer proxySrv.Close()

	// tools/call with no matching rule should be forwarded (default allow)
	toolsCallReq := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"unknown_tool","arguments":{}}}`
	resp, err := http.Post(proxySrv.URL, "application/json", strings.NewReader(toolsCallReq))
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("X-MCP-Audit-Blocked") == "true" {
		t.Fatal("expected no block for default-allow (no --default-deny flag)")
	}
	if targetCalls != 1 {
		t.Fatalf("expected 1 target call for default allow, got %d", targetCalls)
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if _, ok := result["error"]; ok {
		t.Fatalf("expected no error in default-allow response, got: %v", result)
	}
}

// Scenario: Per-tool count tracked
// WHEN three tools/call requests for tool run_command pass through the proxy
// THEN the session counter for run_command reads 3
func TestE2EPolicySessionCounters(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`))
	}))
	defer targetServer.Close()

	policyYAML := `
rules:
  - action: allow
    priority: 10
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

	// Send three tools/call requests for run_command
	for i := range 3 {
		runReq := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"run_command","arguments":{"cmd":"ls"}}}`, i+1)
		resp, err := http.Post(proxySrv.URL, "application/json", strings.NewReader(runReq))
		if err != nil {
			t.Fatalf("run_command request %d: %v", i, err)
		}
		resp.Body.Close()
	}

	// Send one request for a different tool
	fetchReq := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"fetch","arguments":{}}}`
	resp, err := http.Post(proxySrv.URL, "application/json", strings.NewReader(fetchReq))
	if err != nil {
		t.Fatalf("fetch request: %v", err)
	}
	resp.Body.Close()

	// Check /__audit/stats endpoint
	statsResp, err := http.Get(proxySrv.URL + "/__audit/stats")
	if err != nil {
		t.Fatalf("stats request: %v", err)
	}
	defer statsResp.Body.Close()

	var stats map[string]any
	if err := json.NewDecoder(statsResp.Body).Decode(&stats); err != nil {
		t.Fatalf("decode stats: %v", err)
	}

	total, _ := stats["total"].(float64)
	if total != 4 {
		t.Errorf("expected total count 4, got %v", total)
	}

	tools, _ := stats["tools"].(map[string]any)
	runCount, _ := tools["run_command"].(float64)
	if runCount != 3 {
		t.Errorf("expected run_command count 3, got %v", runCount)
	}
	fetchCount, _ := tools["fetch"].(float64)
	if fetchCount != 1 {
		t.Errorf("expected fetch count 1, got %v", fetchCount)
	}
}

// Scenario: Policy allow with block-critical
// WHEN a policy allows the request but --block-critical is set
// and the server response triggers a CRITICAL finding
// THEN the response is blocked as before
func TestE2EPolicyAllowWithBlockCritical(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"Leaked: AKIAIOSFODNN7EXAMPLE"}]}}`))
	}))
	defer targetServer.Close()

	policyYAML := `
rules:
  - action: allow
    priority: 10
    method: "*"
`
	policyPath := writePolicyFile(t, policyYAML)
	cfg := proxy.Config{
		TargetURL:       targetServer.URL,
		BlockCritical:   true,
		MaxResponseSize: 65536,
		PolicyPath:      policyPath,
	}
	p := proxy.New(cfg)

	handler := p.Handler()
	proxySrv := httptest.NewServer(handler)
	defer proxySrv.Close()

	toolsCallReq := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"leak","arguments":{}}}`
	resp, err := http.Post(proxySrv.URL, "application/json", strings.NewReader(toolsCallReq))
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("X-MCP-Audit-Blocked") != "true" {
		t.Fatal("expected block despite policy allow because block-critical is set")
	}

	var blockResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&blockResp); err != nil {
		t.Fatalf("decode blocked response: %v", err)
	}
	errObj, ok := blockResp["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error in blocked response: %v", blockResp)
	}
	code, _ := errObj["code"].(float64)
	if code != -32000 {
		t.Errorf("expected error code -32000 for block-critical, got %v", code)
	}
	msg, _ := errObj["message"].(string)
	if !strings.Contains(msg, "Blocked by mcp-audit") {
		t.Errorf("expected 'Blocked by mcp-audit' in message, got: %q", msg)
	}
}
