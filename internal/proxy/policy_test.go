package proxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPolicyValid(t *testing.T) {
	yaml := `
rules:
  - action: deny
    priority: 10
    method: tools/call
    tool: run_command
    description: "Block command execution"
    conditions:
      params.arguments.command:
        op: regex
        value: "rm\\s+-rf"
  - action: allow
    priority: 20
    method: tools/list
  - action: audit
    priority: 30
    method: "*"
`
	path := writeTempPolicy(t, yaml)
	cfg, err := LoadPolicy(path)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if len(cfg.Rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(cfg.Rules))
	}
	if cfg.Rules[0].Action != "deny" {
		t.Errorf("expected rule 0 action deny, got %s", cfg.Rules[0].Action)
	}
	if cfg.Rules[0].Priority != 10 {
		t.Errorf("expected rule 0 priority 10, got %d", cfg.Rules[0].Priority)
	}
	if cfg.Rules[0].Method != "tools/call" {
		t.Errorf("expected rule 0 method tools/call, got %s", cfg.Rules[0].Method)
	}
	if cfg.Rules[0].Tool != "run_command" {
		t.Errorf("expected rule 0 tool run_command, got %s", cfg.Rules[0].Tool)
	}
	if cfg.Rules[1].Action != "allow" {
		t.Errorf("expected rule 1 action allow, got %s", cfg.Rules[1].Action)
	}
	if cfg.Rules[2].Action != "audit" {
		t.Errorf("expected rule 2 action audit, got %s", cfg.Rules[2].Action)
	}
}

func TestLoadPolicySortedByPriority(t *testing.T) {
	yaml := `
rules:
  - action: audit
    priority: 30
    method: "*"
  - action: deny
    priority: 10
    method: tools/call
    tool: run_command
  - action: allow
    priority: 20
    method: tools/list
`
	path := writeTempPolicy(t, yaml)
	cfg, err := LoadPolicy(path)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if len(cfg.Rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(cfg.Rules))
	}
	if cfg.Rules[0].Priority != 10 {
		t.Errorf("expected rule 0 priority 10, got %d", cfg.Rules[0].Priority)
	}
	if cfg.Rules[1].Priority != 20 {
		t.Errorf("expected rule 1 priority 20, got %d", cfg.Rules[1].Priority)
	}
	if cfg.Rules[2].Priority != 30 {
		t.Errorf("expected rule 2 priority 30, got %d", cfg.Rules[2].Priority)
	}
}

func TestLoadPolicyMissingFile(t *testing.T) {
	_, err := LoadPolicy("/nonexistent/policy.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "read policy file") {
		t.Errorf("expected 'read policy file' error, got: %v", err)
	}
}

func TestLoadPolicyMalformedYAML(t *testing.T) {
	yaml := `rules:
  - action: deny
    priority: 10
method: standalone`
	path := writeTempPolicy(t, yaml)
	_, err := LoadPolicy(path)
	if err == nil {
		t.Fatal("expected error for malformed YAML with inconsistent indentation")
	}
}

func TestLoadPolicyUnknownAction(t *testing.T) {
	yaml := `
rules:
  - action: block
    priority: 10
    method: tools/call
`
	path := writeTempPolicy(t, yaml)
	_, err := LoadPolicy(path)
	if err == nil {
		t.Fatal("expected error for unknown action")
	}
	if !strings.Contains(err.Error(), "unknown action") {
		t.Errorf("expected 'unknown action' error, got: %v", err)
	}
}

func TestLoadPolicyMissingMethod(t *testing.T) {
	yaml := `
rules:
  - action: deny
    priority: 10
`
	path := writeTempPolicy(t, yaml)
	_, err := LoadPolicy(path)
	if err == nil {
		t.Fatal("expected error for missing method")
	}
	if !strings.Contains(err.Error(), "method is required") {
		t.Errorf("expected 'method is required' error, got: %v", err)
	}
}

func TestLoadPolicyDuplicatePriorities(t *testing.T) {
	yaml := `
rules:
  - action: allow
    priority: 10
    method: tools/list
  - action: deny
    priority: 10
    method: tools/call
`
	path := writeTempPolicy(t, yaml)
	_, err := LoadPolicy(path)
	if err == nil {
		t.Fatal("expected error for duplicate priorities")
	}
	if !strings.Contains(err.Error(), "duplicate priority") {
		t.Errorf("expected 'duplicate priority' error, got: %v", err)
	}
}

func TestEvaluateAllowFirstMatch(t *testing.T) {
	yaml := `
rules:
  - action: allow
    priority: 10
    method: tools/list
  - action: deny
    priority: 20
    method: tools/list
`
	cfg := mustLoadPolicy(t, yaml)
	eng := NewPolicyEngine(cfg, false)
	action, desc := eng.Evaluate("tools/list", "", nil)
	if action != "allow" {
		t.Errorf("expected allow, got %s (desc: %s)", action, desc)
	}
}

func TestEvaluateDenyOverridesLowerPriorityAllow(t *testing.T) {
	yaml := `
rules:
  - action: allow
    priority: 20
    method: tools/call
    tool: read_file
  - action: deny
    priority: 10
    method: tools/call
    tool: read_file
`
	cfg := mustLoadPolicy(t, yaml)
	eng := NewPolicyEngine(cfg, false)
	action, _ := eng.Evaluate("tools/call", "read_file", nil)
	if action != "deny" {
		t.Errorf("expected deny (higher priority), got %s", action)
	}
}

func TestEvaluateDefaultAllow(t *testing.T) {
	yaml := `
rules:
  - action: deny
    priority: 10
    method: tools/call
    tool: run_command
`
	cfg := mustLoadPolicy(t, yaml)
	eng := NewPolicyEngine(cfg, false)
	action, _ := eng.Evaluate("tools/list", "", nil)
	if action != "allow" {
		t.Errorf("expected allow (default), got %s", action)
	}
}

func TestEvaluateDefaultDeny(t *testing.T) {
	yaml := `
rules:
  - action: allow
    priority: 10
    method: tools/list
`
	cfg := mustLoadPolicy(t, yaml)
	eng := NewPolicyEngine(cfg, true)
	action, _ := eng.Evaluate("tools/call", "some_tool", nil)
	if action != "deny" {
		t.Errorf("expected deny (default), got %s", action)
	}
}

func TestEvaluateGlobMethodMatching(t *testing.T) {
	yaml := `
rules:
  - action: deny
    priority: 10
    method: tools/*
`
	cfg := mustLoadPolicy(t, yaml)
	eng := NewPolicyEngine(cfg, false)

	tests := []struct {
		method string
		denied bool
	}{
		{"tools/call", true},
		{"tools/list", true},
		{"initialize", false},
		{"notifications/initialized", false},
	}
	for _, tt := range tests {
		action, _ := eng.Evaluate(tt.method, "", nil)
		denied := action == "deny"
		if denied != tt.denied {
			t.Errorf("method=%q: expected denied=%v, got action=%q", tt.method, tt.denied, action)
		}
	}
}

func TestEvaluateGlobToolMatching(t *testing.T) {
	yaml := `
rules:
  - action: deny
    priority: 10
    method: tools/call
    tool: read_*
`
	cfg := mustLoadPolicy(t, yaml)
	eng := NewPolicyEngine(cfg, false)

	tests := []struct {
		tool   string
		denied bool
	}{
		{"read_file", true},
		{"read_directory", true},
		{"write_file", false},
	}
	for _, tt := range tests {
		action, _ := eng.Evaluate("tools/call", tt.tool, nil)
		denied := action == "deny"
		if denied != tt.denied {
			t.Errorf("tool=%q: expected denied=%v, got action=%q", tt.tool, tt.denied, action)
		}
	}
}

func TestEvaluateConditionEquals(t *testing.T) {
	yaml := `
rules:
  - action: deny
    priority: 10
    method: tools/call
    tool: fetch
    conditions:
      params.arguments.url:
        op: equals
        value: "http://evil.com"
`
	cfg := mustLoadPolicy(t, yaml)
	eng := NewPolicyEngine(cfg, false)

	action, _ := eng.Evaluate("tools/call", "fetch", map[string]any{
		"name": "fetch",
		"arguments": map[string]any{
			"url": "http://evil.com",
		},
	})
	if action != "deny" {
		t.Errorf("expected deny for matching condition, got %s", action)
	}

	action2, _ := eng.Evaluate("tools/call", "fetch", map[string]any{
		"name": "fetch",
		"arguments": map[string]any{
			"url": "http://good.com",
		},
	})
	if action2 == "deny" {
		t.Errorf("expected allow for non-matching condition, got %s", action2)
	}
}

func TestEvaluateConditionContains(t *testing.T) {
	yaml := `
rules:
  - action: deny
    priority: 10
    method: tools/call
    tool: fetch
    conditions:
      params.arguments.url:
        op: contains
        value: "/etc"
`
	cfg := mustLoadPolicy(t, yaml)
	eng := NewPolicyEngine(cfg, false)

	action, _ := eng.Evaluate("tools/call", "fetch", map[string]any{
		"arguments": map[string]any{
			"url": "file:///etc/passwd",
		},
	})
	if action != "deny" {
		t.Errorf("expected deny for contains match, got %s", action)
	}
}

func writeTempPolicy(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write temp policy: %v", err)
	}
	return path
}
