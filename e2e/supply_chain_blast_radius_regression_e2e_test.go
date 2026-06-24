package e2e_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestE2E_SCBR_EvidenceWithRandomKeyWritesKeyFile(t *testing.T) {
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
	evidencePath := filepath.Join(t.TempDir(), "evidence-random-key.json")

	_, stderr, code := runMCPAudit(t, bin, home, "static", "--no-color",
		"--no-project-config", "--no-cve-scan",
		"--export-evidence", evidencePath)
	if code != 0 && code != 3 {
		t.Fatalf("evidence export with random key failed: %d", code)
	}

	if _, err := os.Stat(evidencePath); os.IsNotExist(err) {
		t.Fatal("evidence file was not created with random key")
	}

	keyPath := evidencePath + ".key"
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("evidence key file was not created: %v", err)
	}
	keyStr := strings.TrimSpace(string(keyData))
	if len(keyStr) != 64 {
		t.Fatalf("key file content is not 64 hex chars: got %d", len(keyStr))
	}
	if _, err := hex.DecodeString(keyStr); err != nil {
		t.Fatalf("key file content is not valid hex: %v", err)
	}

	keyFileInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("failed to stat key file: %v", err)
	}
	if keyFileInfo.Mode().Perm() != 0600 {
		t.Fatalf("key file has wrong permissions: %v", keyFileInfo.Mode().Perm())
	}

	if !strings.Contains(stderr, "Evidence HMAC key written to:") {
		t.Fatal("stderr does not contain key file path message")
	}
}

func TestE2E_SCBR_EvidenceFileCorruptedDoesNotCrash(t *testing.T) {
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
	evidencePath := filepath.Join(t.TempDir(), "corrupted-evidence.json")

	if err := os.WriteFile(evidencePath, []byte(`{not valid json at all`), 0644); err != nil {
		t.Fatalf("write corrupted file: %v", err)
	}

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json", "--no-color",
		"--no-project-config", "--no-cve-scan",
		"--export-evidence", evidencePath)
	if code != 0 && code != 3 {
		t.Fatalf("static with overwriting corrupted evidence failed: %d", code)
	}

	if !json.Valid([]byte(out)) {
		t.Error("output is not valid JSON after corrupted evidence overwrite")
	}

	data, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatalf("read evidence after overwrite: %v", err)
	}

	var bundle map[string]any
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatalf("re-parse evidence after overwrite: %v", err)
	}
	if v, ok := bundle["format_version"].(string); !ok || v != "1.0" {
		t.Errorf("expected format_version 1.0 after overwrite, got %v", bundle["format_version"])
	}
}

func TestE2E_SCBR_ComplianceSummaryHasFrameworkStructure(t *testing.T) {
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
	result := runStaticJSONWithCVE(t, bin, home, "--blast-radius")

	summary, ok := result["compliance_summary"]
	if !ok {
		t.Log("no compliance_summary in output (expected when no findings have compliance tags)")
		return
	}

	sm, ok := summary.(map[string]any)
	if !ok {
		t.Errorf("compliance_summary is not an object, got %T", summary)
		return
	}

	if len(sm) == 0 {
		t.Log("compliance_summary is empty (no compliance-tagged findings)")
		return
	}

	t.Logf("compliance_summary has %d frameworks", len(sm))
	for fw, controls := range sm {
		ctrlMap, ok := controls.(map[string]any)
		if !ok {
			t.Errorf("compliance_summary[%q] is not an object, got %T", fw, controls)
			continue
		}
		for ctrl, count := range ctrlMap {
			if _, ok := count.(float64); !ok {
				t.Errorf("compliance_summary[%q][%q] count is not a number", fw, ctrl)
			}
		}
	}
}

func TestE2E_SCBR_AllFlagsFunctional(t *testing.T) {
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

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json", "--no-color",
		"--no-project-config", "--no-cve-scan",
		"--blast-radius", "--blast-radius-depth", "3",
		"--compliance-framework", "all")
	if code != 0 && code != 3 {
		t.Fatalf("all blast-radius flags failed: %d", code)
	}
	if !json.Valid([]byte(out)) {
		t.Error("output is not valid JSON with all blast-radius flags")
	}
}

func TestE2E_SCBR_RegressionStaticScanWithBlastFlags(t *testing.T) {
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
	out, _, code := runMCPAudit(t, bin, home, "static", "--no-color",
		"--no-project-config", "--no-cve-scan", "--blast-radius",
		"--compliance-framework", "owasp-llm", "--blast-radius-depth", "3")
	if code != 0 && code != 3 {
		t.Fatalf("static with all blast-radius flags failed: %d", code)
	}
	if !strings.Contains(out, "PASS") {
		t.Error("static scan with blast-radius flags missing 'PASS'")
	}
	if strings.Contains(out, "panic") || strings.Contains(out, "fatal") {
		t.Error("static scan with blast-radius flags contains panic/fatal")
	}
}

func TestE2E_SCBR_RegressionAllOutputFormatsWithBlastRadius(t *testing.T) {
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

	tests := []struct {
		format, want string
	}{
		{"json", `"severity"`},
		{"sarif", `"$schema"`},
		{"junit", "testsuite"},
	}

	for _, tc := range tests {
		t.Run(tc.format, func(t *testing.T) {
			out, _, code := runMCPAudit(t, bin, home, "static", "--format", tc.format,
				"--no-color", "--no-project-config", "--no-cve-scan",
				"--blast-radius", "--compliance-framework", "all")
			if code != 0 && code != 3 {
				t.Errorf("format %s failed with code %d", tc.format, code)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("format %s missing expected string %q", tc.format, tc.want)
			}
		})
	}
}

func TestE2E_SCBR_EvidenceEmptyFindings(t *testing.T) {
	bin := buildBinary(t)

	claudeCfg := `{"mcpServers": {}}`

	home := setupHomeDir(t, claudeCfg)
	evidencePath := filepath.Join(t.TempDir(), "evidence-empty.json")
	const keyHex = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json", "--no-color",
		"--no-project-config", "--no-cve-scan",
		"--export-evidence", evidencePath, "--evidence-key", keyHex)
	if code != 0 {
		t.Logf("empty config scan returned code %d (expected 0)", code)
	}

	data, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatalf("read evidence file: %v", err)
	}

	var bundle map[string]any
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatalf("parse evidence bundle: %v", err)
	}
	if v, ok := bundle["format_version"].(string); !ok || v != "1.0" {
		t.Errorf("expected format_version 1.0, got %v", bundle["format_version"])
	}
	if cv, ok := bundle["chain_valid"].(bool); !ok || !cv {
		t.Errorf("expected chain_valid: true, got %v", bundle["chain_valid"])
	}
	_ = out
}

func TestE2E_SCBR_NoCveScanWithBlastRadius(t *testing.T) {
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
	result := runStaticJSON(t, bin, home, "--blast-radius")

	chains, ok := result["blastRadiusChains"]
	if !ok {
		t.Log("blastRadiusChains field not present with --no-cve-scan (expected)")
	} else if arr, ok := chains.([]any); ok && len(arr) > 0 {
		t.Errorf("expected empty blastRadiusChains with --no-cve-scan, got %d chains", len(arr))
	}
}

func TestE2E_SCBR_SCBRExportEvidenceKeyFile(t *testing.T) {
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
	evidencePath := filepath.Join(t.TempDir(), "evidence-key-file.json")

	_, stderr, code := runMCPAudit(t, bin, home, "static", "--no-color",
		"--no-project-config", "--no-cve-scan",
		"--export-evidence", evidencePath)

	if code != 0 && code != 3 {
		t.Fatalf("evidence export failed: %d", code)
	}

	if _, err := os.Stat(evidencePath); os.IsNotExist(err) {
		t.Fatal("evidence file not created")
	}

	keyPath := evidencePath + ".key"
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("evidence key file was not created: %v", err)
	}
	keyStr := strings.TrimSpace(string(keyData))
	if len(keyStr) != 64 {
		t.Fatalf("key file content is not 64 hex chars: got %d", len(keyStr))
	}
	if _, err := hex.DecodeString(keyStr); err != nil {
		t.Fatalf("key file content is not valid hex: %v", err)
	}

	keyFileInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("failed to stat key file: %v", err)
	}
	if keyFileInfo.Mode().Perm() != 0600 {
		t.Fatalf("key file has wrong permissions: %v", keyFileInfo.Mode().Perm())
	}

	if !strings.Contains(stderr, "Evidence HMAC key written to:") {
		t.Fatal("stderr does not contain key file path message")
	}
}
