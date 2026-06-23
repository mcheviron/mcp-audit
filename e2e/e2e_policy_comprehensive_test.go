package e2e_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mostafaelataby-cheviron/mcp-audit/internal/proxy"
)

// Scenario: Glob method match
// WHEN a tools/call request arrives and a rule specifies method: tools/*
// THEN the rule matches
func TestE2EPolicyGlobMethodMatch(t *testing.T) {
	targetCalled := false
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetCalled = true
		t.Error("target should not be reached for denied request")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer targetServer.Close()

	policyYAML := `
rules:
  - action: deny
    priority: 10
    method: tools/*
    description: "Block all tools calls"
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

	toolsCallReq := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"anytool","arguments":{}}}`
	resp, err := http.Post(proxySrv.URL, "application/json", strings.NewReader(toolsCallReq))
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("X-MCP-Audit-Blocked") != "true" {
		t.Fatal("expected X-MCP-Audit-Blocked header for glob method deny")
	}
	if targetCalled {
		t.Fatal("target should not be called when glob method matches deny rule")
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	errObj, ok := result["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error, got: %v", result)
	}
	code, _ := errObj["code"].(float64)
	if code != -32001 {
		t.Errorf("expected error code -32001, got %v", code)
	}
}

// Scenario: Tool name glob match
// WHEN a tools/call for tool read_file arrives and a rule specifies tool: read_*
// THEN the rule matches
func TestE2EPolicyGlobToolNameMatch(t *testing.T) {
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
    tool: read_*
    description: "Block all read tools"
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

	// tools/call for read_file should be denied
	readReq := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/passwd"}}}`
	resp, err := http.Post(proxySrv.URL, "application/json", strings.NewReader(readReq))
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	resp.Body.Close()
	if resp.Header.Get("X-MCP-Audit-Blocked") != "true" {
		t.Fatal("expected block for glob tool pattern match")
	}
	if targetCalled {
		t.Fatal("target should not be called when glob tool matches deny rule")
	}

	// tools/call for write_file should be allowed (glob read_* does not match write_file)
	targetCalled = false
	writeReq := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{}}}`
	resp2, err := http.Post(proxySrv.URL, "application/json", strings.NewReader(writeReq))
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.Header.Get("X-MCP-Audit-Blocked") == "true" {
		t.Fatal("expected write_file to NOT be blocked by read_* glob")
	}
}

// Scenario: Method mismatch
// WHEN a initialize request arrives and a rule specifies method: tools/list
// THEN the rule does not match
func TestE2EPolicyMethodMismatch(t *testing.T) {
	targetCalls := 0
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetCalls++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer targetServer.Close()

	policyYAML := `
rules:
  - action: deny
    priority: 10
    method: tools/list
    description: "Deny tools/list"
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

	// initialize should pass through (no matching deny rule)
	initReq := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	resp, err := http.Post(proxySrv.URL, "application/json", strings.NewReader(initReq))
	if err != nil {
		t.Fatalf("proxy init request: %v", err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("X-MCP-Audit-Blocked") == "true" {
		t.Fatal("initialize should not be blocked by tools/list rule")
	}
	if targetCalls != 1 {
		t.Fatalf("expected 1 target call for init, got %d", targetCalls)
	}
}

// Scenario: Single condition match (contains operator)
// WHEN a rule has conditions: {params.arguments.path: {op: contains, value: "/etc"}}
// and the request contains params.arguments.path: "/etc/passwd"
// THEN the condition matches
func TestE2EPolicyConditionContains(t *testing.T) {
	targetCalled := false
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetCalled = true
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer targetServer.Close()

	policyYAML := `
rules:
  - action: deny
    priority: 10
    method: tools/call
    tool: read_file
    description: "Block access to /etc"
    conditions:
      params.arguments.path:
        op: contains
        value: "/etc"
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

	// Request with /etc/passwd should be denied (contains /etc)
	etcReq := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/passwd"}}}`
	resp, err := http.Post(proxySrv.URL, "application/json", strings.NewReader(etcReq))
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("X-MCP-Audit-Blocked") != "true" {
		t.Fatal("expected block for request with /etc path")
	}
	if targetCalled {
		t.Fatal("target should not be called when condition matches deny rule")
	}

	// Request with /tmp should be allowed (does not contain /etc)
	targetCalled = false
	tmpReq := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/foo.txt"}}}`
	resp2, err := http.Post(proxySrv.URL, "application/json", strings.NewReader(tmpReq))
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.Header.Get("X-MCP-Audit-Blocked") == "true" {
		t.Fatal("expected /tmp path to NOT be blocked by /etc condition")
	}
}

// Scenario: All conditions must match (AND logic)
// WHEN a rule has two conditions and only one is satisfied
// THEN the rule does not match
func TestE2EPolicyConditionANDLogic(t *testing.T) {
	targetCalls := 0
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetCalls++
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
    description: "Block fetch to internal URLs"
    conditions:
      params.arguments.url:
        op: contains
        value: "internal"
      params.arguments.method:
        op: equals
        value: "POST"
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

	// Request matching only one condition (url contains "internal" but method is not POST)
	partialReq := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch","arguments":{"url":"http://internal.corp/api","method":"GET"}}}`
	resp, err := http.Post(proxySrv.URL, "application/json", strings.NewReader(partialReq))
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("X-MCP-Audit-Blocked") == "true" {
		t.Fatal("expected request with partial condition match to NOT be blocked")
	}
	if targetCalls != 1 {
		t.Fatalf("expected 1 target call for partial condition match, got %d", targetCalls)
	}

	// Request matching BOTH conditions should be denied
	targetCalls = 0
	fullMatchReq := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fetch","arguments":{"url":"http://internal.corp/api","method":"POST"}}}`
	resp2, err := http.Post(proxySrv.URL, "application/json", strings.NewReader(fullMatchReq))
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.Header.Get("X-MCP-Audit-Blocked") != "true" {
		t.Fatal("expected block when both AND conditions match")
	}
}
