package e2e_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestE2E_BlastRadius_RelatedFindingsInJSON(t *testing.T) {
	t.Parallel()
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
	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json", "--no-color")
	if code != 0 && code != 3 {
		t.Fatalf("static failed: %d\noutput:\n%s", code, out)
	}

	var wrapper struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &wrapper); err != nil {
		t.Fatalf("json parse: %v", err)
	}

	hasRelated := false
	hasCompliance := false
	for _, f := range wrapper.Findings {
		if _, ok := f["related_findings"]; ok {
			hasRelated = true
		}
		if _, ok := f["compliance"]; ok {
			hasCompliance = true
		}
		if typ, _ := f["type"].(string); typ == "cve" {
			rel, _ := f["related_findings"].([]any)
			if len(rel) > 0 {
				t.Logf("CVE finding has %d related findings", len(rel))
			}
			comp, _ := f["compliance"].([]any)
			t.Logf("CVE finding has %d compliance tags", len(comp))
		}
	}
	if !hasRelated {
		t.Error("expected related_findings field in JSON output")
	}
	if !hasCompliance {
		t.Error("expected compliance field in JSON output")
	}
}

func TestE2E_BlastRadius_ChainOutput(t *testing.T) {
	t.Parallel()
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
	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json", "--no-color", "--blast-radius")
	if code != 0 && code != 3 {
		t.Fatalf("static with --blast-radius failed: %d\noutput:\n%s", code, out)
	}

	var wrapper struct {
		BlastRadiusChains []map[string]any `json:"blastRadiusChains"`
		ComplianceSummary map[string]any   `json:"compliance_summary"`
	}
	if err := json.Unmarshal([]byte(out), &wrapper); err != nil {
		t.Fatalf("json parse: %v", err)
	}

	if wrapper.BlastRadiusChains == nil {
		t.Log("no blastRadiusChains in output (no CVE findings to chain from)")
	} else {
		t.Logf("blastRadiusChains array has %d chains", len(wrapper.BlastRadiusChains))
	}

	if wrapper.ComplianceSummary == nil {
		t.Log("no compliance_summary in output")
	} else {
		t.Log("compliance_summary present in JSON output")
	}
}

func TestE2E_BlastRadius_ComplianceFrameworkFilter(t *testing.T) {
	t.Parallel()
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
	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json", "--no-color", "--compliance-framework", "owasp-llm")
	if code != 0 && code != 3 {
		t.Fatalf("static with --compliance-framework failed: %d\noutput:\n%s", code, out)
	}

	if !json.Valid([]byte(out)) {
		t.Error("output is not valid JSON")
	}

	var wrapper struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &wrapper); err != nil {
		t.Fatalf("json parse: %v", err)
	}

	t.Logf("compliance-framework owasp-llm: %d findings", len(wrapper.Findings))
}

func TestE2E_BlastRadius_ExportEvidence(t *testing.T) {
	t.Parallel()
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
	evidencePath := filepath.Join(t.TempDir(), "evidence.json")
	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json", "--no-color",
		"--export-evidence", evidencePath)

	if code != 0 && code != 3 {
		t.Fatalf("static with --export-evidence failed: %d\noutput:\n%s", code, out)
	}

	if _, err := os.Stat(evidencePath); os.IsNotExist(err) {
		t.Fatal("evidence file was not created")
	}

	data, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatalf("read evidence file: %v", err)
	}

	var bundle struct {
		FormatVersion string `json:"format_version"`
		ChainValid    bool   `json:"chain_valid"`
		Entries       []any  `json:"entries"`
	}
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatalf("parse evidence bundle: %v", err)
	}
	if bundle.FormatVersion != "1.0" {
		t.Errorf("expected format_version 1.0, got %q", bundle.FormatVersion)
	}
	if !bundle.ChainValid {
		t.Error("expected chain_valid: true")
	}
	t.Logf("evidence file: %d entries, chain_valid=%v", len(bundle.Entries), bundle.ChainValid)
}
