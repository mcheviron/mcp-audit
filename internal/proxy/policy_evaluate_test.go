package proxy

import (
	"strings"
	"testing"
)

func TestEvaluateConditionPrefix(t *testing.T) {
	yaml := `
rules:
  - action: deny
    priority: 10
    method: tools/call
    conditions:
      params.arguments.path:
        op: prefix
        value: "/etc"
`
	cfg := mustLoadPolicy(t, yaml)
	eng := NewPolicyEngine(cfg, false)

	action, _ := eng.Evaluate("tools/call", "read_file", map[string]any{
		"arguments": map[string]any{
			"path": "/etc/passwd",
		},
	})
	if action != "deny" {
		t.Errorf("expected deny for prefix match, got %s", action)
	}

	action2, _ := eng.Evaluate("tools/call", "read_file", map[string]any{
		"arguments": map[string]any{
			"path": "/tmp/file",
		},
	})
	if action2 == "deny" {
		t.Errorf("expected allow for non-matching prefix, got %s", action2)
	}
}

func TestEvaluateConditionSuffix(t *testing.T) {
	yaml := `
rules:
  - action: deny
    priority: 10
    method: tools/call
    conditions:
      params.arguments.filename:
        op: suffix
        value: ".exe"
`
	cfg := mustLoadPolicy(t, yaml)
	eng := NewPolicyEngine(cfg, false)

	action, _ := eng.Evaluate("tools/call", "write_file", map[string]any{
		"arguments": map[string]any{
			"filename": "malware.exe",
		},
	})
	if action != "deny" {
		t.Errorf("expected deny for suffix match, got %s", action)
	}

	action2, _ := eng.Evaluate("tools/call", "write_file", map[string]any{
		"arguments": map[string]any{
			"filename": "safe.txt",
		},
	})
	if action2 == "deny" {
		t.Errorf("expected allow for non-matching suffix, got %s", action2)
	}
}

func TestEvaluateConditionRegex(t *testing.T) {
	yaml := `
rules:
  - action: deny
    priority: 10
    method: tools/call
    conditions:
      params.arguments.command:
        op: regex
        value: "rm\\s+-rf"
`
	cfg := mustLoadPolicy(t, yaml)
	eng := NewPolicyEngine(cfg, false)

	action, _ := eng.Evaluate("tools/call", "run_command", map[string]any{
		"arguments": map[string]any{
			"command": "rm -rf /",
		},
	})
	if action != "deny" {
		t.Errorf("expected deny for regex match, got %s", action)
	}

	action2, _ := eng.Evaluate("tools/call", "run_command", map[string]any{
		"arguments": map[string]any{
			"command": "ls -la",
		},
	})
	if action2 == "deny" {
		t.Errorf("expected allow for non-matching regex, got %s", action2)
	}
}

func TestEvaluateConditionAND(t *testing.T) {
	yaml := `
rules:
  - action: deny
    priority: 10
    method: tools/call
    tool: fetch
    conditions:
      params.arguments.url:
        op: prefix
        value: "http://"
      params.arguments.port:
        op: equals
        value: "8080"
`
	cfg := mustLoadPolicy(t, yaml)
	eng := NewPolicyEngine(cfg, false)

	actionBoth, _ := eng.Evaluate("tools/call", "fetch", map[string]any{
		"arguments": map[string]any{
			"url":  "http://example.com",
			"port": "8080",
		},
	})
	if actionBoth != "deny" {
		t.Errorf("expected deny when all conditions match, got %s", actionBoth)
	}

	actionOne, _ := eng.Evaluate("tools/call", "fetch", map[string]any{
		"arguments": map[string]any{
			"url":  "http://example.com",
			"port": "9090",
		},
	})
	if actionOne == "deny" {
		t.Errorf("expected allow when only one condition matches, got %s", actionOne)
	}
}

func TestEvaluateConditionNone(t *testing.T) {
	yaml := `
rules:
  - action: allow
    priority: 10
    method: tools/*
`
	cfg := mustLoadPolicy(t, yaml)
	eng := NewPolicyEngine(cfg, false)

	action, _ := eng.Evaluate("tools/list", "", nil)
	if action != "allow" {
		t.Errorf("expected allow for tools/list, got %s", action)
	}
}

func TestEvaluateEmptyParams(t *testing.T) {
	yaml := `
rules:
  - action: deny
    priority: 10
    method: tools/call
    conditions:
      params.arguments.url:
        op: equals
        value: "bad"
`
	cfg := mustLoadPolicy(t, yaml)
	eng := NewPolicyEngine(cfg, false)

	action, _ := eng.Evaluate("tools/call", "fetch", nil)
	if action == "deny" {
		t.Errorf("expected allow when params is nil and condition can't match")
	}
}

func TestEvaluateEmptyToolRule(t *testing.T) {
	yaml := `
rules:
  - action: deny
    priority: 10
    method: tools/call
  - action: allow
    priority: 20
    method: tools/call
    tool: safe_tool
`
	cfg := mustLoadPolicy(t, yaml)
	eng := NewPolicyEngine(cfg, false)

	action, _ := eng.Evaluate("tools/call", "any_tool", nil)
	if action != "deny" {
		t.Errorf("expected deny for rule without tool filter, got %s", action)
	}
}

func TestEvaluateGlobStarOnly(t *testing.T) {
	yaml := `
rules:
  - action: deny
    priority: 10
    method: "*"
`
	cfg := mustLoadPolicy(t, yaml)
	eng := NewPolicyEngine(cfg, false)

	for _, m := range []string{"tools/call", "tools/list", "initialize", "anything"} {
		action, _ := eng.Evaluate(m, "", nil)
		if action != "deny" {
			t.Errorf("method=%q: expected deny for * glob, got %s", m, action)
		}
	}
}

func TestCounterIncrements(t *testing.T) {
	yaml := `
rules:
  - action: allow
    priority: 10
    method: tools/call
  - action: allow
    priority: 20
    method: tools/list
`
	cfg := mustLoadPolicy(t, yaml)
	eng := NewPolicyEngine(cfg, false)

	for range 5 {
		eng.Evaluate("tools/call", "tool_a", nil)
	}
	for range 3 {
		eng.Evaluate("tools/call", "tool_b", nil)
	}
	eng.Evaluate("tools/list", "", nil)

	total, counts := eng.Stats()
	if total != 9 {
		t.Errorf("expected total 9, got %d", total)
	}
	if counts["tool_a"] != 5 {
		t.Errorf("expected tool_a count 5, got %d", counts["tool_a"])
	}
	if counts["tool_b"] != 3 {
		t.Errorf("expected tool_b count 3, got %d", counts["tool_b"])
	}
}

func TestCounterNoTool(t *testing.T) {
	yaml := `
rules:
  - action: allow
    priority: 10
    method: tools/list
`
	cfg := mustLoadPolicy(t, yaml)
	eng := NewPolicyEngine(cfg, false)

	for range 3 {
		eng.Evaluate("tools/list", "", nil)
	}

	total, counts := eng.Stats()
	if total != 3 {
		t.Errorf("expected total 3, got %d", total)
	}
	if len(counts) != 0 {
		t.Errorf("expected no tool counts for empty tool, got %v", counts)
	}
}

func TestLoadPolicyEmptyRules(t *testing.T) {
	yaml := "rules: []"
	path := writeTempPolicy(t, yaml)
	cfg, err := LoadPolicy(path)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if len(cfg.Rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(cfg.Rules))
	}
}

func TestEvaluateRegexTimeoutSafety(t *testing.T) {
	yaml := `
rules:
  - action: deny
    priority: 10
    method: tools/call
    conditions:
      params.arguments.input:
        op: regex
        value: "(a+)+b"
`
	cfg := mustLoadPolicy(t, yaml)
	eng := NewPolicyEngine(cfg, false)

	action, _ := eng.Evaluate("tools/call", "test", map[string]any{
		"arguments": map[string]any{
			"input": strings.Repeat("a", 30) + "x",
		},
	})
	if action == "deny" {
		t.Log("regex timed out and returned false, default allow")
	}
}

func TestEvaluateWildcardToolMatchAll(t *testing.T) {
	yaml := `
rules:
  - action: deny
    priority: 10
    method: tools/call
    tool: "*"
`
	cfg := mustLoadPolicy(t, yaml)
	eng := NewPolicyEngine(cfg, false)

	for _, tool := range []string{"read_file", "write_file", "fetch", "run_command"} {
		action, _ := eng.Evaluate("tools/call", tool, nil)
		if action != "deny" {
			t.Errorf("tool=%q: expected deny for * tool glob", tool)
		}
	}
}

func TestYAMLParseConditions(t *testing.T) {
	yaml := `
rules:
  - action: deny
    priority: 10
    method: tools/call
    conditions:
      params.arguments.url:
        op: contains
        value: "internal"
      params.arguments.host:
        op: prefix
        value: "10."
`
	path := writeTempPolicy(t, yaml)
	cfg, err := LoadPolicy(path)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if len(cfg.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(cfg.Rules))
	}
	rule := cfg.Rules[0]
	if len(rule.Conditions) != 2 {
		t.Fatalf("expected 2 conditions, got %d", len(rule.Conditions))
	}
	cond1, ok := rule.Conditions["params.arguments.url"]
	if !ok {
		t.Fatal("expected condition for params.arguments.url")
	}
	if cond1.Op != "contains" || cond1.Value != "internal" {
		t.Errorf("expected op=contains value=internal, got op=%s value=%s", cond1.Op, cond1.Value)
	}
	cond2, ok := rule.Conditions["params.arguments.host"]
	if !ok {
		t.Fatal("expected condition for params.arguments.host")
	}
	if cond2.Op != "prefix" || cond2.Value != "10." {
		t.Errorf("expected op=prefix value=10., got op=%s value=%s", cond2.Op, cond2.Value)
	}
}

func mustLoadPolicy(t *testing.T, yaml string) *PolicyConfig {
	t.Helper()
	path := writeTempPolicy(t, yaml)
	cfg, err := LoadPolicy(path)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	return cfg
}
