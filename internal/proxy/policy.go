package proxy

import (
	"cmp"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
)

type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
	ActionAudit Action = "audit"
)

type ConditionOp string

const (
	OpEquals   ConditionOp = "equals"
	OpContains ConditionOp = "contains"
	OpPrefix   ConditionOp = "prefix"
	OpSuffix   ConditionOp = "suffix"
	OpRegex    ConditionOp = "regex"
)

type PolicyCondition struct {
	Field string      `json:"field"`
	Op    ConditionOp `json:"op"`
	Value string      `json:"value"`
}

type PolicyRule struct {
	Action      Action                       `json:"action"`
	Priority    int                          `json:"priority"`
	Method      string                       `json:"method"`
	Tool        string                       `json:"tool,omitempty"`
	Description string                       `json:"description,omitempty"`
	Conditions  map[string]PolicyConditionOp `json:"conditions,omitempty"`
}

type PolicyConditionOp struct {
	Op            ConditionOp `json:"op"`
	Value         string      `json:"value"`
	compiledRegex *regexp.Regexp
}

type PolicyConfig struct {
	Rules []PolicyRule `json:"rules"`
}

type PolicyEngine struct {
	rules       []PolicyRule
	defaultDeny bool
	mu          sync.RWMutex
	totalReqs   int64
	toolCounts  map[string]int64
	toolMu      sync.Mutex
}

func NewPolicyEngine(cfg *PolicyConfig, defaultDeny bool) *PolicyEngine {
	for i := range cfg.Rules {
		for field, cond := range cfg.Rules[i].Conditions {
			if cond.Op == OpRegex {
				re, err := regexp.Compile(cond.Value)
				if err != nil {
					slog.Warn("invalid regex in policy condition", "field", field, "pattern", cond.Value, "err", err)
					continue
				}
				cond.compiledRegex = re
				cfg.Rules[i].Conditions[field] = cond
			}
		}
	}
	slices.SortFunc(cfg.Rules, func(a, b PolicyRule) int {
		return cmp.Compare(a.Priority, b.Priority)
	})
	return &PolicyEngine{
		rules:       cfg.Rules,
		defaultDeny: defaultDeny,
		toolCounts:  make(map[string]int64),
	}
}

func (e *PolicyEngine) Evaluate(method, tool string, params map[string]any) (Action, string) {
	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()

	e.toolMu.Lock()
	e.totalReqs++
	if tool != "" {
		e.toolCounts[tool]++
	}
	e.toolMu.Unlock()

	for _, rule := range rules {
		if !matchGlob(rule.Method, method) {
			continue
		}
		if rule.Tool != "" && !matchGlob(rule.Tool, tool) {
			continue
		}
		if !e.evaluateConditions(rule, params) {
			continue
		}
		return rule.Action, rule.Description
	}

	if e.defaultDeny {
		return ActionDeny, "Default deny: no matching allow rule"
	}
	return ActionAllow, "No matching rule, default allow"
}

func (e *PolicyEngine) Stats() (total int64, toolCounts map[string]int64) {
	e.toolMu.Lock()
	defer e.toolMu.Unlock()
	tc := make(map[string]int64, len(e.toolCounts))
	maps.Copy(tc, e.toolCounts)
	return e.totalReqs, tc
}

func LoadPolicy(path string) (*PolicyConfig, error) {
	//nolint:gosec // path from user --policy flag, intended
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}

	cfg, err := parsePolicyYAML(data)
	if err != nil {
		return nil, err
	}

	for i, rule := range cfg.Rules {
		if rule.Action != ActionAllow && rule.Action != ActionDeny && rule.Action != ActionAudit {
			return nil, fmt.Errorf("rule %d: unknown action %q", i, rule.Action)
		}
		if rule.Method == "" {
			return nil, fmt.Errorf("rule %d: method is required", i)
		}
	}

	seen := map[int]int{}
	for i, rule := range cfg.Rules {
		if prev, ok := seen[rule.Priority]; ok {
			return nil, fmt.Errorf("duplicate priority %d between rule %d and rule %d", rule.Priority, prev, i)
		}
		seen[rule.Priority] = i
	}

	slices.SortFunc(cfg.Rules, func(a, b PolicyRule) int {
		return cmp.Compare(a.Priority, b.Priority)
	})

	return cfg, nil
}

func matchGlob(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	prefix, ok := strings.CutSuffix(pattern, "*")
	if ok {
		return strings.HasPrefix(value, prefix)
	}
	return pattern == value
}

func extractNestedValue(params map[string]any, field string) string {
	parts := strings.Split(field, ".")
	startIdx := 0
	if len(parts) > 0 && parts[0] == "params" {
		startIdx = 1
	}
	if startIdx >= len(parts) {
		return ""
	}
	current := any(params)
	for _, part := range parts[startIdx:] {
		m, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current, ok = m[part]
		if !ok {
			return ""
		}
	}
	if current == nil {
		return ""
	}
	if s, ok := current.(string); ok {
		return s
	}
	b, err := json.Marshal(current)
	if err != nil {
		return ""
	}
	return strings.Trim(string(b), "\"")
}

func (e *PolicyEngine) evaluateCondition(cond PolicyConditionOp, actual string) bool {
	switch cond.Op {
	case OpEquals:
		return actual == cond.Value
	case OpContains:
		return strings.Contains(actual, cond.Value)
	case OpPrefix:
		return strings.HasPrefix(actual, cond.Value)
	case OpSuffix:
		return strings.HasSuffix(actual, cond.Value)
	case OpRegex:
		if cond.compiledRegex == nil {
			return false
		}
		if len(actual) > 64*1024 {
			slog.Warn("regex input exceeds cap; skipping", "pattern", cond.Value)
			return false
		}
		return cond.compiledRegex.MatchString(actual)
	default:
		return false
	}
}

func (e *PolicyEngine) evaluateConditions(rule PolicyRule, params map[string]any) bool {
	if len(rule.Conditions) == 0 {
		return true
	}
	for field, cond := range rule.Conditions {
		actual := extractNestedValue(params, field)
		if !e.evaluateCondition(cond, actual) {
			return false
		}
	}
	return true
}
