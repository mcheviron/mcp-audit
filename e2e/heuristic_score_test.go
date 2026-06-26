package e2e_test

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestE2EJsonOutputIncludesScore(t *testing.T) {
	t.Parallel()
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
		t.Fatalf("probe exited with scan error code 2\noutput:\n%s", out)
	}

	var wrapper struct {
		Findings []map[string]any `json:"findings"`
		Scores   []map[string]any `json:"scores"`
	}
	if err := json.Unmarshal([]byte(out), &wrapper); err != nil {
		t.Fatalf("json parse failed: %v\noutput:\n%s", err, out)
	}

	hasScore := false
	for _, f := range wrapper.Findings {
		if s, ok := f["score"]; ok {
			if val, ok := s.(float64); ok {
				if val >= 0 && val <= 100 {
					hasScore = true
					break
				}
			}
		}
	}
	if !hasScore {
		t.Log("no finding had score field, checking scores array")
		if len(wrapper.Scores) == 0 {
			t.Error("expected scores array or score field in findings")
		} else {
			for _, s := range wrapper.Scores {
				if scoreVal, ok := s["score"]; ok {
					if val, ok := scoreVal.(float64); ok && val >= 0 && val <= 100 {
						hasScore = true
						break
					}
				}
			}
			if !hasScore {
				t.Error("expected score between 0 and 100 in scores array")
			}
		}
	}
}

func TestE2EMinSecurityScoreExitCode(t *testing.T) {
	t.Parallel()
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

	_, _, codeHigh := runMCPAudit(t, bin, home, "probe", "--format", "json", "--heuristic", "--min-security-score", "100")
	if codeHigh == 0 {
		t.Errorf("expected non-zero exit when min-security-score=100 and scores are lower, got %d", codeHigh)
	}

	_, _, codeLow := runMCPAudit(t, bin, home, "probe", "--format", "json", "--min-security-score", "0")
	if codeLow == 2 {
		t.Errorf("expected exit code from report (not gate), but got 2 with --min-security-score=0")
	}
}

func TestE2EScoreWeightsFlag(t *testing.T) {
	t.Parallel()
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

	out, _, code := runMCPAudit(t, bin, home, "probe", "--format", "json",
		"--score-weights", "0.20,0.20,0.20,0.20,0.20")
	if code == 2 {
		t.Fatalf("probe exited with scan error code 2\noutput:\n%s", out)
	}

	var wrapper struct {
		Findings []map[string]any `json:"findings"`
		Scores   []map[string]any `json:"scores"`
	}
	if err := json.Unmarshal([]byte(out), &wrapper); err != nil {
		t.Fatalf("json parse failed: %v\noutput:\n%s", err, out)
	}

	if len(wrapper.Scores) > 0 {
		for _, s := range wrapper.Scores {
			if factors, ok := s["riskFactors"]; ok {
				if factors == nil {
					t.Error("riskFactors should not be nil")
				}
			}
		}
	}
}

func TestE2EInvalidScoreWeights(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)

	claudeCfg := `{
		"mcpServers": {}
	}`

	home := setupHomeDir(t, claudeCfg)

	_, _, code := runMCPAudit(t, bin, home, "static",
		"--score-weights", "0.40,0.40,0.40,0,0")
	if code != 4 {
		t.Errorf("expected exit code 4 for invalid weights (sum != 1.0), got %d", code)
	}
}
