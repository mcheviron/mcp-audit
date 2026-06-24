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
)

func runStaticJSONWithCVE(t *testing.T, bin, home string, extraArgs ...string) map[string]any {
	t.Helper()
	args := append([]string{"static", "--format", "json", "--no-color", "--no-project-config"}, extraArgs...)
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

func TestE2E_SCBR_RelatedFindingsCVECredential(t *testing.T) {
	bin := buildBinary(t)

	claudeCfg := `{
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
			},
			"memory": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-memory"]
			}
		}
	}`

	home := setupHomeDir(t, claudeCfg)
	result := runStaticJSONWithCVE(t, bin, home, "--blast-radius")

	findings := getFindings(t, result)

	cveWithRelated := 0
	cveWithoutRelated := 0
	hasCVE := false
	for _, f := range findings {
		typ, _ := f["type"].(string)
		if typ != "cve" {
			continue
		}
		hasCVE = true
		server, _ := f["server"].(string)
		rel, _ := f["related_findings"].([]any)

		otherFindingsOnServer := 0
		for _, f2 := range findings {
			if f2["type"].(string) != "cve" {
				if s, _ := f2["server"].(string); s == server {
					otherFindingsOnServer++
				}
			}
		}

		if len(rel) > 0 {
			cveWithRelated++
			t.Logf("CVE finding on server %q has %d related_findings (other findings on server: %d)",
				server, len(rel), otherFindingsOnServer)
			for _, r := range rel {
				ref, ok := r.(map[string]any)
				if !ok {
					continue
				}
				if _, ok := ref["id"]; !ok {
					t.Error("related_finding missing 'id' field")
				}
				if _, ok := ref["type"]; !ok {
					t.Error("related_finding missing 'type' field")
				}
			}
		} else {
			cveWithoutRelated++
		}
	}

	if !hasCVE {
		t.Log("no CVE findings produced (NVD/GitHub may be unreachable); skipping related_findings verification")
	} else {
		t.Logf("CVEs with related_findings: %d, without: %d", cveWithRelated, cveWithoutRelated)
	}
}

func TestE2E_SCBR_NoRelatedFindingsIsolatedCVE(t *testing.T) {
	bin := buildBinary(t)

	claudeCfg := `{
		"mcpServers": {
			"unique-srv": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-everything"]
			}
		}
	}`

	home := setupHomeDir(t, claudeCfg)
	result := runStaticJSONWithCVE(t, bin, home, "--blast-radius")

	findings := getFindings(t, result)

	hasCVE := false
	for _, f := range findings {
		typ, _ := f["type"].(string)
		if typ != "cve" {
			continue
		}
		hasCVE = true
		server, _ := f["server"].(string)

		otherOnServer := 0
		for _, f2 := range findings {
			if s, _ := f2["server"].(string); s == server && f2["type"].(string) != "cve" {
				otherOnServer++
			}
		}

		rel, _ := f["related_findings"].([]any)
		if otherOnServer == 0 {
			if len(rel) > 0 {
				t.Errorf("expected empty related_findings for CVE on server %q with no other findings, got %d", server, len(rel))
			}
		}
	}

	if !hasCVE {
		t.Log("no CVE findings produced; cannot verify isolated CVE related_findings check")
	}
}

func TestE2E_SCBR_BlastRadiusChainsStructure(t *testing.T) {
	bin := buildBinary(t)

	claudeCfg := `{
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
			},
			"memory": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-memory"]
			}
		}
	}`

	home := setupHomeDir(t, claudeCfg)
	result := runStaticJSONWithCVE(t, bin, home, "--blast-radius")

	chains, ok := result["blastRadiusChains"]
	if !ok {
		t.Log("blastRadiusChains field not present (expected when no CVE findings exist)")
		return
	}

	arr, ok := chains.([]any)
	if !ok {
		t.Fatalf("blastRadiusChains is not an array, got %T", chains)
	}

	for i, c := range arr {
		chain, ok := c.(map[string]any)
		if !ok {
			t.Errorf("blastRadiusChains[%d] is not an object", i)
			continue
		}

		if _, ok := chain["max_severity"]; !ok {
			t.Errorf("chain[%d] missing 'max_severity'", i)
		}

		hops, _ := chain["hops"].([]any)
		if len(hops) == 0 {
			t.Errorf("chain[%d] has empty hops", i)
			continue
		}

		firstHop, ok := hops[0].(map[string]any)
		if !ok {
			continue
		}
		if typ, _ := firstHop["type"].(string); typ != "cve" {
			t.Errorf("chain[%d] first hop type expected 'cve', got %q", i, typ)
		}

		for j, h := range hops {
			hop, ok := h.(map[string]any)
			if !ok {
				t.Errorf("chain[%d] hop[%d] is not an object", i, j)
				continue
			}
			for _, field := range []string{"type", "id", "label"} {
				if _, ok := hop[field]; !ok {
					t.Errorf("chain[%d] hop[%d] missing field '%s'", i, j, field)
				}
			}
		}

		t.Logf("chain[%d]: %d hops, max_severity=%v, truncated=%v",
			i, len(hops), chain["max_severity"], chain["truncated"])
	}
}

func TestE2E_SCBR_DepthTruncationWithCVEs(t *testing.T) {
	bin := buildBinary(t)

	claudeCfg := `{
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
			},
			"memory": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-memory"]
			}
		}
	}`

	home := setupHomeDir(t, claudeCfg)
	result := runStaticJSONWithCVE(t, bin, home, "--blast-radius", "--blast-radius-depth", "1")

	chains, ok := result["blastRadiusChains"]
	if !ok {
		t.Log("no blastRadiusChains (no CVE findings)")
		return
	}

	arr, _ := chains.([]any)
	for i, c := range arr {
		chain, _ := c.(map[string]any)
		hops, _ := chain["hops"].([]any)
		if len(hops) > 2 {
			trunc, _ := chain["truncated"].(bool)
			if !trunc {
				t.Errorf("chain[%d] has %d hops with depth=1 but not truncated", i, len(hops))
			}
		}
	}
}

func TestE2E_SCBR_ComplianceFrameworkAll(t *testing.T) {
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

	frameworks := []string{"soc2", "nist-ai-rmf", "owasp-llm", "mitre-atlas", "eu-ai-act"}

	for _, fw := range frameworks {
		t.Run(fw, func(t *testing.T) {
			out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json", "--no-color",
				"--no-project-config", "--no-cve-scan", "--compliance-framework", fw)
			if code != 0 && code != 3 {
				t.Errorf("compliance-framework %q failed with code %d", fw, code)
			}
			if !json.Valid([]byte(out)) {
				t.Errorf("compliance-framework %q produced invalid JSON", fw)
			}
		})
	}
}

func TestE2E_SCBR_ComplianceFrameworkMultiple(t *testing.T) {
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
		"--no-project-config", "--no-cve-scan", "--compliance-framework", "soc2,owasp-llm")
	if code != 0 && code != 3 {
		t.Fatalf("multiple frameworks failed: %d", code)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("json parse: %v", err)
	}

	findings := getFindings(t, result)
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
			if fw != "SOC 2" && fw != "OWASP LLM Top-10" {
				t.Errorf("finding has compliance framework %q, expected only SOC 2 or OWASP LLM Top-10", fw)
			}
		}
	}
}

func TestE2E_SCBR_ComplianceFrameworkInvalid(t *testing.T) {
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
		"--no-project-config", "--no-cve-scan", "--compliance-framework", "nonexistent-framework")
	if code == 2 {
		t.Errorf("invalid compliance-framework should not cause scan error code 2\noutput:\n%s", out)
	}
}

func TestE2E_SCBR_TableOutputShowsBlastRadius(t *testing.T) {
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
		"--no-project-config", "--no-cve-scan", "--blast-radius")
	if code != 0 && code != 3 {
		t.Fatalf("static --blast-radius table failed: %d", code)
	}

	if !strings.Contains(out, "Security Scores") {
		t.Error("table output missing 'Security Scores' section with --blast-radius")
	}

	if strings.Contains(out, "Blast-Radius Chains") {
		t.Log("table output contains 'Blast-Radius Chains' section")
	}
}

func TestE2E_SCBR_EvidenceBundleComprehensive(t *testing.T) {
	bin := buildBinary(t)

	claudeCfg := `{
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
			},
			"memory": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-memory"]
			}
		}
	}`

	home := setupHomeDir(t, claudeCfg)
	evidencePath := filepath.Join(t.TempDir(), "evidence-comprehensive.json")
	const keyHex = "deadbeef00112233445566778899aabbccddeeff00112233445566778899aabb"

	out, stderr, code := runMCPAudit(t, bin, home, "static", "--format", "json", "--no-color",
		"--no-project-config", "--no-cve-scan",
		"--export-evidence", evidencePath, "--evidence-key", keyHex)
	if code != 0 && code != 3 {
		t.Fatalf("evidence export failed: %d\nstderr:\n%s", code, stderr)
	}

	if _, err := os.Stat(evidencePath); os.IsNotExist(err) {
		t.Fatal("evidence file was not created")
	}

	data, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatalf("read evidence file: %v", err)
	}

	var bundle map[string]any
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatalf("parse evidence bundle: %v", err)
	}

	requiredFields := []string{
		"scan_timestamp", "findings", "entries",
		"chain_valid", "format_version",
	}
	for _, field := range requiredFields {
		if _, ok := bundle[field]; !ok {
			t.Errorf("evidence bundle missing required field: %s", field)
		}
	}

	if v, ok := bundle["format_version"].(string); !ok || v != "1.0" {
		t.Errorf("expected format_version 1.0, got %v", bundle["format_version"])
	}

	if cv, ok := bundle["chain_valid"].(bool); !ok || !cv {
		t.Errorf("expected chain_valid: true, got %v", bundle["chain_valid"])
	}

	entries, ok := bundle["entries"].([]any)
	if !ok {
		t.Fatal("entries is not an array")
	}

	if len(entries) == 0 {
		t.Error("evidence bundle has empty entries array")
	}

	key, _ := hex.DecodeString(keyHex)
	prevHash := ""
	for i, e := range entries {
		entry, ok := e.(map[string]any)
		if !ok {
			t.Errorf("entry[%d] is not an object", i)
			continue
		}
		id, _ := entry["id"].(string)
		dataStr, _ := entry["data"].(string)
		hash, _ := entry["hash"].(string)

		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(id))
		mac.Write([]byte(dataStr))
		mac.Write([]byte(prevHash))
		expected := hex.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(expected), []byte(hash)) {
			t.Errorf("HMAC mismatch at entry[%d] id=%q", i, id)
		}
		prevHash = hash
	}
	t.Logf("evidence bundle: %d entries, all HMAC verified", len(entries))

	_ = out
}
