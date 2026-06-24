package e2e_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/go-set"
)

func setupTestConfig(t *testing.T, name string) (string, string) {
	t.Helper()
	home := t.TempDir()
	claudeDir := filepath.Join(home, "Library", "Application Support", "Claude")
	if err := os.MkdirAll(claudeDir, 0755); err != nil {
		t.Fatalf("mkdir claude dir: %v", err)
	}
	cfg := map[string]any{
		"mcpServers": map[string]any{
			name: map[string]any{
				"command": "npx",
				"args":    []string{"-y", "@modelcontextprotocol/server-filesystem", "/tmp"},
			},
		},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(claudeDir, "claude_desktop_config.json"),
		data, 0644,
	); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return home, name
}

func runStaticJSON(t *testing.T, bin, home string, extraArgs ...string) map[string]any {
	t.Helper()
	args := append([]string{"static", "--format", "json", "--no-color", "--no-cve-scan", "--no-project-config"}, extraArgs...)
	out, _, code := runMCPAudit(t, bin, home, args...)
	if code != 0 && code != 3 {
		t.Fatalf("static failed (code %d):\n%s", code, out)
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("json parse: %v", err)
	}
	return result
}

func getFindings(t *testing.T, result map[string]any) []map[string]any {
	t.Helper()
	raw, ok := result["findings"]
	if !ok {
		t.Fatal("no findings key in output")
	}
	arr, ok := raw.([]any)
	if !ok {
		t.Fatalf("findings is not an array, got %T", raw)
	}
	findings := make([]map[string]any, len(arr))
	for i, v := range arr {
		findings[i], ok = v.(map[string]any)
		if !ok {
			t.Fatalf("finding[%d] is not an object, got %T", i, v)
		}
	}
	return findings
}

func verifiableHMAC(entries []any, keyHex string) bool {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return false
	}
	prevHash := ""
	for _, e := range entries {
		entry, ok := e.(map[string]any)
		if !ok {
			return false
		}
		id, _ := entry["id"].(string)
		data, _ := entry["data"].(string)
		hash, _ := entry["hash"].(string)
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(id))
		mac.Write([]byte(data))
		mac.Write([]byte(prevHash))
		expected := hex.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(expected), []byte(hash)) {
			return false
		}
		prevHash = hash
	}
	return true
}

func TestE2E_EvidenceBundleStructure(t *testing.T) {
	bin := buildBinary(t)
	home, _ := setupTestConfig(t, "filesystem")

	evidencePath := filepath.Join(t.TempDir(), "evidence.json")
	const keyHex = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"

	_, _, code := runMCPAudit(t, bin, home, "static", "--format", "json", "--no-color",
		"--no-cve-scan", "--no-project-config",
		"--export-evidence", evidencePath, "--evidence-key", keyHex)
	if code != 0 && code != 3 {
		t.Fatalf("static with evidence export failed: %d", code)
	}

	data, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatalf("read evidence file: %v", err)
	}

	var bundle map[string]any
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatalf("parse evidence bundle: %v", err)
	}

	for _, field := range []string{"scan_timestamp", "findings", "entries", "chain_valid", "format_version"} {
		if _, ok := bundle[field]; !ok {
			t.Errorf("evidence bundle missing field: %s", field)
		}
	}

	if v, ok := bundle["format_version"].(string); !ok || v != "1.0" {
		t.Errorf("expected format_version 1.0, got %v", bundle["format_version"])
	}
}

func TestE2E_HMACChainVerifiable(t *testing.T) {
	bin := buildBinary(t)
	home, _ := setupTestConfig(t, "filesystem")

	evidencePath := filepath.Join(t.TempDir(), "evidence.json")
	const keyHex = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"

	_, _, code := runMCPAudit(t, bin, home, "static", "--format", "json", "--no-color",
		"--no-cve-scan", "--no-project-config",
		"--export-evidence", evidencePath, "--evidence-key", keyHex)
	if code != 0 && code != 3 {
		t.Fatalf("static with evidence export failed: %d", code)
	}

	data, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatalf("read evidence file: %v", err)
	}

	var bundle map[string]any
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatalf("parse evidence bundle: %v", err)
	}

	if cv, ok := bundle["chain_valid"].(bool); !ok || !cv {
		t.Errorf("expected chain_valid: true, got %v", bundle["chain_valid"])
	}

	entries, ok := bundle["entries"].([]any)
	if !ok {
		t.Fatal("entries is not an array")
	}

	if !verifiableHMAC(entries, keyHex) {
		t.Error("HMAC chain verification failed — entries do not verify with same key")
	}
}

func TestE2E_HMACChainFailsWithWrongKey(t *testing.T) {
	bin := buildBinary(t)
	home, _ := setupTestConfig(t, "filesystem")

	evidencePath := filepath.Join(t.TempDir(), "evidence.json")
	const keyHex = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	const wrongKey = "ff0000000000000000000000000000ff00000000000000000000000000000000"

	_, _, code := runMCPAudit(t, bin, home, "static", "--format", "json", "--no-color",
		"--no-cve-scan", "--no-project-config",
		"--export-evidence", evidencePath, "--evidence-key", keyHex)
	if code != 0 && code != 3 {
		t.Fatalf("static failed: %d", code)
	}

	data, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatalf("read evidence file: %v", err)
	}

	var bundle map[string]any
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatalf("parse evidence bundle: %v", err)
	}

	entries, ok := bundle["entries"].([]any)
	if !ok {
		t.Fatal("entries is not an array")
	}

	if verifiableHMAC(entries, wrongKey) {
		t.Error("HMAC chain verified with WRONG key — should have failed")
	}
}

func TestE2E_NoCveFindingsProducesEmptyChains(t *testing.T) {
	bin := buildBinary(t)
	home, _ := setupTestConfig(t, "filesystem")

	result := runStaticJSON(t, bin, home, "--blast-radius")

	chains, ok := result["blastRadiusChains"]
	if !ok {
		t.Log("blastRadiusChains field not present (expected for no CVE findings)")
	} else if arr, ok := chains.([]any); ok && len(arr) > 0 {
		t.Errorf("expected empty blastRadiusChains, got %d chains", len(arr))
	}
}

func TestE2E_BlastRadiusJSONStructure(t *testing.T) {
	bin := buildBinary(t)
	home, _ := setupTestConfig(t, "filesystem")

	result := runStaticJSON(t, bin, home, "--blast-radius")

	chains, hasChains := result["blastRadiusChains"]
	if hasChains {
		if arr, ok := chains.([]any); ok {
			for i, c := range arr {
				chain, ok := c.(map[string]any)
				if !ok {
					t.Errorf("blastRadiusChains[%d] is not an object", i)
					continue
				}
				for _, f := range []string{"hops", "max_severity", "truncated"} {
					if _, ok := chain[f]; !ok {
						t.Errorf("chain[%d] missing field: %s", i, f)
					}
				}
			}
		}
	}

	summary, ok := result["compliance_summary"]
	if !ok {
		t.Log("no compliance_summary in output")
	} else {
		if _, ok := summary.(map[string]any); !ok {
			t.Errorf("compliance_summary is not an object, got %T", summary)
		}
	}
}

func TestE2E_BlastRadiusTableOutput(t *testing.T) {
	bin := buildBinary(t)
	home, _ := setupTestConfig(t, "filesystem")

	out, _, code := runMCPAudit(t, bin, home, "static", "--no-color",
		"--no-cve-scan", "--no-project-config", "--blast-radius")
	if code != 0 && code != 3 {
		t.Fatalf("static failed: %d", code)
	}

	if !strings.Contains(out, "Security Scores") {
		t.Error("table output missing 'Security Scores' section")
	}
}

func TestE2E_BlastRadiusDepthTruncation(t *testing.T) {
	bin := buildBinary(t)
	home, _ := setupTestConfig(t, "filesystem")

	result := runStaticJSON(t, bin, home, "--blast-radius", "--blast-radius-depth", "2")

	chains, ok := result["blastRadiusChains"]
	if ok {
		if arr, ok := chains.([]any); ok {
			for _, c := range arr {
				chain, ok := c.(map[string]any)
				if !ok {
					continue
				}
				hops, _ := chain["hops"].([]any)
				if len(hops) > 2 {
					trunc, _ := chain["truncated"].(bool)
					if !trunc {
						t.Errorf("chain has %d hops but depth=2 and not truncated", len(hops))
					}
				}
			}
		}
	}
}

func TestE2E_ComplianceFrameworkFilterOWASPOnly(t *testing.T) {
	bin := buildBinary(t)
	home, _ := setupTestConfig(t, "filesystem")

	result := runStaticJSON(t, bin, home, "--compliance-framework", "owasp-llm")
	findings := getFindings(t, result)

	for _, f := range findings {
		comp, ok := f["compliance"].([]any)
		if !ok || len(comp) == 0 {
			t.Logf("finding for %s has no compliance tags", f["server"])
			continue
		}
		for _, c := range comp {
			ct, ok := c.(map[string]any)
			if !ok {
				continue
			}
			fw, _ := ct["framework"].(string)
			if fw != "OWASP LLM Top-10" {
				t.Errorf("finding has compliance tag for framework %q, expected only OWASP LLM Top-10", fw)
			}
		}
	}
}

func TestE2E_ComplianceMultipleFrameworks(t *testing.T) {
	bin := buildBinary(t)
	home, _ := setupTestConfig(t, "filesystem")

	result := runStaticJSON(t, bin, home, "--compliance-framework", "soc2,owasp-llm")
	findings := getFindings(t, result)

	validFW := set.From[string]([]string{"SOC 2", "OWASP LLM Top-10"})
	for _, f := range findings {
		comp, ok := f["compliance"].([]any)
		if !ok || len(comp) == 0 {
			continue
		}
		for _, c := range comp {
			ct, ok := c.(map[string]any)
			if !ok {
				continue
			}
			fw, _ := ct["framework"].(string)
			if !validFW.Contains(fw) {
				t.Errorf("finding has compliance tag for framework %q, expected only soc2 or owasp-llm", fw)
			}
		}
	}
}
