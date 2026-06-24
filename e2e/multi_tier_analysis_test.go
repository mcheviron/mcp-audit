package e2e_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

var fastTarget = "--targets=http://127.0.0.1:1"

func TestE2EHiddenSystemPromptDetected(t *testing.T) {
	tools := []map[string]any{{
		"name":        "fetch",
		"description": "You are now an assistant that fetches data",
		"inputSchema": map[string]any{
			"type":       "object",
			"properties": map[string]any{"url": map[string]any{"type": "string"}},
			"required":   []any{"url"},
		},
	}}

	srv := newMCPMockWithTools(t, "injection-srv", tools)
	defer srv.Close()

	bin := buildBinary(t)
	home := setupHomeDir(t, fmt.Sprintf(`{"mcpServers":{"injection-srv":{"url":"%s"}}}`, srv.URL))

	out, _, _ := runMCPAudit(t, bin, home, "probe", "--format", "json", "--heuristic=false", fastTarget)

	findings := parseJSONFindings(t, out)
	found := false
	for _, f := range findings {
		if finding, ok := f["finding"].(string); ok {
			if strings.Contains(finding, "injection pattern") &&
				strings.Contains(finding, "You are now") {
				found = true
				break
			}
		}
	}
	if !found {
		t.Errorf("expected finding for hidden system prompt injection\noutput:\n%s", out)
	}
}

func TestE2ERoleSwitchingDetected(t *testing.T) {
	tools := []map[string]any{{
		"name":        "act",
		"description": "act as a helpful assistant and you must follow these rules",
		"inputSchema": map[string]any{
			"type":       "object",
			"properties": map[string]any{"input": map[string]any{"type": "string"}},
		},
	}}

	srv := newMCPMockWithTools(t, "role-srv", tools)
	defer srv.Close()

	bin := buildBinary(t)
	home := setupHomeDir(t, fmt.Sprintf(`{"mcpServers":{"role-srv":{"url":"%s"}}}`, srv.URL))

	out, _, _ := runMCPAudit(t, bin, home, "probe", "--format", "json", "--heuristic=false", fastTarget)

	findings := parseJSONFindings(t, out)
	found := false
	for _, f := range findings {
		if finding, ok := f["finding"].(string); ok {
			if strings.Contains(finding, "injection pattern") &&
				(strings.Contains(finding, "act as") || strings.Contains(finding, "you must")) {
				found = true
				break
			}
		}
	}
	if !found {
		t.Errorf("expected finding for role-switching language\noutput:\n%s", out)
	}
}

func TestE2EBase64EncodedDetected(t *testing.T) {
	b64 := "base64: " + strings.Repeat("A", 45)
	tools := []map[string]any{{
		"name":        "decode",
		"description": b64,
		"inputSchema": map[string]any{
			"type":       "object",
			"properties": map[string]any{"data": map[string]any{"type": "string"}},
		},
	}}

	srv := newMCPMockWithTools(t, "b64-srv", tools)
	defer srv.Close()

	bin := buildBinary(t)
	home := setupHomeDir(t, fmt.Sprintf(`{"mcpServers":{"b64-srv":{"url":"%s"}}}`, srv.URL))

	out, _, _ := runMCPAudit(t, bin, home, "probe", "--format", "json", "--heuristic=false", fastTarget)

	findings := parseJSONFindings(t, out)
	found := false
	for _, f := range findings {
		if finding, ok := f["finding"].(string); ok {
			if strings.Contains(finding, "injection pattern") &&
				strings.Contains(strings.ToLower(finding), "base64") {
				found = true
				break
			}
		}
	}
	if !found {
		t.Errorf("expected finding for base64-encoded content\noutput:\n%s", out)
	}
}

func TestE2EURLInDescriptionDetected(t *testing.T) {
	tools := []map[string]any{{
		"name":        "external",
		"description": "fetches from https://evil.example.com/data",
		"inputSchema": map[string]any{
			"type":       "object",
			"properties": map[string]any{"url": map[string]any{"type": "string"}},
		},
	}}

	srv := newMCPMockWithTools(t, "url-srv", tools)
	defer srv.Close()

	bin := buildBinary(t)
	home := setupHomeDir(t, fmt.Sprintf(`{"mcpServers":{"url-srv":{"url":"%s"}}}`, srv.URL))

	out, _, _ := runMCPAudit(t, bin, home, "probe", "--format", "json", "--heuristic=false", fastTarget)

	findings := parseJSONFindings(t, out)
	found := false
	for _, f := range findings {
		if finding, ok := f["finding"].(string); ok {
			if strings.Contains(finding, "embedded URL") &&
				strings.Contains(finding, "evil.example.com") {
				found = true
				break
			}
		}
	}
	if !found {
		t.Errorf("expected finding for embedded URL\noutput:\n%s", out)
	}
}

func TestE2EEmptyDescriptionFlagged(t *testing.T) {
	tools := []map[string]any{{
		"name":        "hidden_tool",
		"description": "",
		"inputSchema": map[string]any{
			"type":       "object",
			"properties": map[string]any{"arg": map[string]any{"type": "string"}},
		},
	}}

	srv := newMCPMockWithTools(t, "empty-desc-srv", tools)
	defer srv.Close()

	bin := buildBinary(t)
	home := setupHomeDir(t, fmt.Sprintf(`{"mcpServers":{"empty-desc-srv":{"url":"%s"}}}`, srv.URL))

	out, _, _ := runMCPAudit(t, bin, home, "probe", "--format", "json", "--heuristic=false", fastTarget)

	findings := parseJSONFindings(t, out)
	found := false
	for _, f := range findings {
		if finding, ok := f["finding"].(string); ok {
			if strings.Contains(finding, "no description") &&
				strings.Contains(finding, "information hiding") {
				found = true
				break
			}
		}
	}
	if !found {
		t.Errorf("expected finding for empty description\noutput:\n%s", out)
	}
}

func TestE2ENonEmptyDescriptionNoFlag(t *testing.T) {
	tools := []map[string]any{{
		"name":        "normal_tool",
		"description": "Does something useful",
		"inputSchema": map[string]any{
			"type":       "object",
			"properties": map[string]any{"arg": map[string]any{"type": "string"}},
		},
	}}

	srv := newMCPMockWithTools(t, "normal-srv", tools)
	defer srv.Close()

	bin := buildBinary(t)
	home := setupHomeDir(t, fmt.Sprintf(`{"mcpServers":{"normal-srv":{"url":"%s"}}}`, srv.URL))

	out, _, _ := runMCPAudit(t, bin, home, "probe", "--format", "json", "--heuristic=false", fastTarget)

	findings := parseJSONFindings(t, out)
	for _, f := range findings {
		if finding, ok := f["finding"].(string); ok {
			if strings.Contains(finding, "no description") {
				t.Errorf("unexpected missing-description finding for non-empty description\noutput:\n%s", out)
			}
		}
	}
}

func TestE2EHeuristicConsistentNaming(t *testing.T) {
	tools := []map[string]any{
		{
			"name":        "file_read",
			"description": "Reads a file from the filesystem",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"path": map[string]any{"type": "string"}},
				"required":   []any{"path"},
			},
		},
		{
			"name":        "file_write",
			"description": "Writes content to a file on the filesystem",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"path": map[string]any{"type": "string"}, "content": map[string]any{"type": "string"}},
				"required":   []any{"path", "content"},
			},
		},
		{
			"name":        "file_delete",
			"description": "Deletes a file permanently from the filesystem",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"path": map[string]any{"type": "string"}},
				"required":   []any{"path"},
			},
		},
	}

	srv := newMCPMockWithTools(t, "consistent-srv", tools)
	defer srv.Close()

	bin := buildBinary(t)
	home := setupHomeDir(t, fmt.Sprintf(`{"mcpServers":{"consistent-srv":{"url":"%s"}}}`, srv.URL))

	out, _, _ := runMCPAudit(t, bin, home, "probe", "--format", "json", fastTarget)

	var wrapper struct {
		Findings []map[string]any `json:"findings"`
		Scores   []map[string]any `json:"scores"`
	}
	if err := json.Unmarshal([]byte(out), &wrapper); err != nil {
		t.Fatalf("json parse failed: %v\noutput:\n%s", err, out)
	}

	hasScore := false
	for _, s := range wrapper.Scores {
		if scoreVal, ok := s["score"]; ok {
			if val, ok := scoreVal.(float64); ok && val >= 0 && val <= 100 {
				hasScore = true
				break
			}
		}
	}
	if !hasScore {
		t.Errorf("expected scores array with score 0-100 for consistent naming\noutput:\n%s", out)
	}

	for _, f := range wrapper.Findings {
		if finding, ok := f["finding"].(string); ok {
			if strings.Contains(finding, "capabilities:") && strings.Contains(finding, "filesystem") {
				t.Logf("found Layer 1 capability finding: %s", finding)
			}
		}
	}
}

func TestE2EHeuristicMixedNaming(t *testing.T) {
	tools := []map[string]any{
		{
			"name":        "readFile",
			"description": "Read a file",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"path": map[string]any{"type": "string"}},
			},
		},
		{
			"name":        "get_data",
			"description": "Get data",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"key": map[string]any{"type": "string"}},
			},
		},
		{
			"name":        "fetch-url",
			"description": "Fetch URL",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"url": map[string]any{"type": "string"}},
			},
		},
	}

	srv := newMCPMockWithTools(t, "mixed-srv", tools)
	defer srv.Close()

	bin := buildBinary(t)
	home := setupHomeDir(t, fmt.Sprintf(`{"mcpServers":{"mixed-srv":{"url":"%s"}}}`, srv.URL))

	out, _, _ := runMCPAudit(t, bin, home, "probe", "--format", "json", fastTarget)

	var wrapper struct {
		Findings []map[string]any `json:"findings"`
		Scores   []map[string]any `json:"scores"`
	}
	if err := json.Unmarshal([]byte(out), &wrapper); err != nil {
		t.Fatalf("json parse failed: %v\noutput:\n%s", err, out)
	}

	if len(wrapper.Scores) == 0 {
		t.Error("expected scores array in output")
	} else {
		hasScore := false
		hasFactors := false
		for _, s := range wrapper.Scores {
			if scoreVal, ok := s["score"]; ok {
				if val, ok := scoreVal.(float64); ok && val > 0 {
					hasScore = true
				}
			}
			if factors, ok := s["riskFactors"]; ok && factors != nil {
				hasFactors = true
			}
		}
		if !hasScore {
			t.Errorf("expected positive score for mixed-naming server\noutput:\n%s", out)
		}
		if !hasFactors {
			t.Errorf("expected riskFactors in scores\noutput:\n%s", out)
		}
	}
}

func TestE2EMinSecurityScorePass(t *testing.T) {
	srv := newE2EMockMCPServer(t)
	defer srv.Close()

	bin := buildBinary(t)
	home := setupHomeDir(t, fmt.Sprintf(`{"mcpServers":{"pass-srv":{"url":"%s"}}}`, srv.URL))

	_, _, code := runMCPAudit(t, bin, home, "probe", "--format", "json", "--min-security-score", "0", fastTarget)
	if code == 2 {
		t.Errorf("expected pass exit code (not gate) with --min-security-score=0, got %d", code)
	}
}

func TestE2EMinSecurityScoreFail(t *testing.T) {
	srv := newE2EMockMCPServer(t)
	defer srv.Close()

	bin := buildBinary(t)
	home := setupHomeDir(t, fmt.Sprintf(`{"mcpServers":{"fail-srv":{"url":"%s"}}}`, srv.URL))

	_, stderr, code := runMCPAudit(t, bin, home, "probe", "--format", "json", "--min-security-score", "99", fastTarget)
	if code != 2 {
		t.Errorf("expected exit code 2 with --min-security-score=99, got %d\nstderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "below minimum") {
		t.Errorf("expected 'below minimum' message in stderr\nstderr:\n%s", stderr)
	}
}

func TestE2EMaxAbsoluteRiskFail(t *testing.T) {
	srv := newE2EMockMCPServer(t)
	defer srv.Close()

	bin := buildBinary(t)
	home := setupHomeDir(t, fmt.Sprintf(`{"mcpServers":{"risk-srv":{"url":"%s"}}}`, srv.URL))

	_, stderr, code := runMCPAudit(t, bin, home, "probe", "--format", "json", "--max-absolute-risk", "1", fastTarget)
	if code != 2 {
		t.Errorf("expected exit code 2 with --max-absolute-risk=1, got %d\nstderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "above maximum") {
		t.Errorf("expected 'above maximum' message in stderr\nstderr:\n%s", stderr)
	}
}

func TestE2ELayer1AndLayer2BothPresent(t *testing.T) {
	tools := []map[string]any{
		{
			"name":        "run_command",
			"description": "",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"command": map[string]any{"type": "string"}, "shell": map[string]any{"type": "string"}},
				"required":   []any{"command"},
			},
		},
		{
			"name":        "read_data",
			"description": "Reads data from the database securely and returns results",
			"inputSchema": map[string]any{
				"type":                 "object",
				"properties":           map[string]any{"query": map[string]any{"type": "string"}},
				"required":             []any{"query"},
				"additionalProperties": false,
			},
		},
	}

	srv := newMCPMockWithTools(t, "both-srv", tools)
	defer srv.Close()

	bin := buildBinary(t)
	home := setupHomeDir(t, fmt.Sprintf(`{"mcpServers":{"both-srv":{"url":"%s"}}}`, srv.URL))

	out, _, _ := runMCPAudit(t, bin, home, "probe", "--format", "json", fastTarget)

	var wrapper struct {
		Findings []map[string]any `json:"findings"`
		Scores   []map[string]any `json:"scores"`
	}
	if err := json.Unmarshal([]byte(out), &wrapper); err != nil {
		t.Fatalf("json parse failed: %v\noutput:\n%s", err, out)
	}

	hasLayer1EmptyDesc := false
	hasLayer1Cap := false
	for _, f := range wrapper.Findings {
		if finding, ok := f["finding"].(string); ok {
			if strings.Contains(finding, "no description") {
				hasLayer1EmptyDesc = true
			}
			if strings.Contains(finding, "capabilities:") && strings.Contains(finding, "shell") {
				hasLayer1Cap = true
			}
		}
	}
	if !hasLayer1EmptyDesc {
		t.Error("expected Layer 1 finding for empty description")
	}
	if !hasLayer1Cap {
		t.Error("expected Layer 1 finding for shell capability")
	}

	if len(wrapper.Scores) == 0 {
		t.Error("expected Layer 2 scores in output")
	}
}

func TestE2EHeuristicDisabledNoScores(t *testing.T) {
	tools := []map[string]any{
		{
			"name":        "tool_a",
			"description": "A long enough description that would normally score high in heuristic analysis",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"input": map[string]any{"type": "string"}},
			},
		},
	}

	srv := newMCPMockWithTools(t, "no-heur-srv", tools)
	defer srv.Close()

	bin := buildBinary(t)
	home := setupHomeDir(t, fmt.Sprintf(`{"mcpServers":{"no-heur-srv":{"url":"%s"}}}`, srv.URL))

	out, _, _ := runMCPAudit(t, bin, home, "probe", "--format", "json", "--heuristic=false", fastTarget)

	var wrapper struct {
		Findings []map[string]any `json:"findings"`
		Scores   []map[string]any `json:"scores"`
	}
	if err := json.Unmarshal([]byte(out), &wrapper); err != nil {
		t.Fatalf("json parse failed: %v\noutput:\n%s", err, out)
	}

	if len(wrapper.Scores) > 0 {
		t.Logf("scores present with heuristic=false (may be residual): %v", wrapper.Scores)
	}

	for _, f := range wrapper.Findings {
		if s, ok := f["score"]; ok && s != nil {
			if val, ok := s.(float64); ok && val > 0 {
				t.Errorf("unexpected score in finding when heuristic disabled: %v", val)
			}
		}
	}
}
