package e2e_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestE2ESBOMCycloneDXJSONDefault(t *testing.T) {
	bin := buildBinary(t)
	home := setupHomeDir(t, `{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/tmp"]}}}`)

	stdout, _, code := runMCPAudit(t, bin, home, "sbom")
	if code != 0 {
		t.Fatalf("sbom exit code = %d, want 0", code)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
		t.Fatalf("unmarshal: %v\noutput: %s", err, stdout)
	}
	if parsed["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat = %v, want CycloneDX", parsed["bomFormat"])
	}
	if parsed["specVersion"] != "1.6" {
		t.Errorf("specVersion = %v, want 1.6", parsed["specVersion"])
	}
}

func TestE2ESBOMSPDXTagValue(t *testing.T) {
	bin := buildBinary(t)
	home := setupHomeDir(t, `{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/tmp"]}}}`)

	stdout, _, code := runMCPAudit(t, bin, home, "sbom", "--format", "spdx-tag")
	if code != 0 {
		t.Fatalf("sbom exit code = %d, want 0", code)
	}

	if !strings.Contains(stdout, "SPDXVersion: SPDX-2.3") {
		t.Errorf("output should contain 'SPDXVersion: SPDX-2.3'\n%s", stdout)
	}
	if !strings.Contains(stdout, "DataLicense: CC0-1.0") {
		t.Errorf("output should contain 'DataLicense: CC0-1.0'\n%s", stdout)
	}
}

func TestE2ESBOMOutputFile(t *testing.T) {
	bin := buildBinary(t)
	home := setupHomeDir(t, `{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/tmp"]}}}`)

	outPath := filepath.Join(home, "test-sbom.json")
	_, _, code := runMCPAudit(t, bin, home, "sbom", "--output", outPath)
	if code != 0 {
		t.Fatalf("sbom exit code = %d, want 0", code)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat = %v, want CycloneDX", parsed["bomFormat"])
	}
}

func TestE2ESBOMCycloneDXXML(t *testing.T) {
	bin := buildBinary(t)
	home := setupHomeDir(t, `{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/tmp"]}}}`)

	stdout, _, code := runMCPAudit(t, bin, home, "sbom", "--format", "cyclonedx-xml")
	if code != 0 {
		t.Fatalf("sbom exit code = %d, want 0", code)
	}

	if !strings.Contains(stdout, "<?xml version") {
		t.Errorf("output should start with XML declaration\n%s", stdout)
	}
	if !strings.Contains(stdout, "cyclonedx.org") {
		t.Errorf("output should contain cyclonedx.org namespace\n%s", stdout)
	}
}

func TestE2ESBOMSPDXJSON(t *testing.T) {
	bin := buildBinary(t)
	home := setupHomeDir(t, `{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/tmp"]}}}`)

	stdout, _, code := runMCPAudit(t, bin, home, "sbom", "--format", "spdx-json")
	if code != 0 {
		t.Fatalf("sbom exit code = %d, want 0", code)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
		t.Fatalf("unmarshal: %v\noutput: %s", err, stdout)
	}
	if parsed["spdxVersion"] != "SPDX-2.3" {
		t.Errorf("spdxVersion = %v, want SPDX-2.3", parsed["spdxVersion"])
	}
	if parsed["SPDXID"] != "SPDXRef-DOCUMENT" {
		t.Errorf("SPDXID = %v, want SPDXRef-DOCUMENT", parsed["SPDXID"])
	}
}

func TestE2ESBOMWithCVEs(t *testing.T) {
	bin := buildBinary(t)
	home := setupHomeDir(t, `{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/tmp"]}}}`)

	stdout, _, code := runMCPAudit(t, bin, home, "sbom", "--with-cves")
	if code != 0 {
		t.Fatalf("sbom --with-cves exit code = %d, want 0", code)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
		t.Fatalf("unmarshal: %v\noutput: %s", err, stdout)
	}
	if parsed["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat = %v, want CycloneDX", parsed["bomFormat"])
	}
	if parsed["specVersion"] != "1.6" {
		t.Errorf("specVersion = %v, want 1.6", parsed["specVersion"])
	}

	vulns, ok := parsed["vulnerabilities"].([]any)
	if ok && len(vulns) > 0 {
		for _, v := range vulns {
			vuln, ok := v.(map[string]any)
			if !ok {
				t.Error("vulnerability should be an object")
				continue
			}
			if _, ok := vuln["id"]; !ok {
				t.Error("vulnerability missing 'id' field")
			}
		}
		t.Logf("SBOM includes %d vulnerabilities", len(vulns))
	} else {
		t.Log("no vulnerabilities found (expected if test package has no known CVEs)")
	}
}

func TestE2ESBOMEmptyConfig(t *testing.T) {
	bin := buildBinary(t)
	home := setupHomeDir(t, `{"mcpServers":{}}`)

	stdout, _, code := runMCPAudit(t, bin, home, "sbom")
	if code != 0 {
		t.Fatalf("sbom exit code = %d, want 0", code)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
		t.Fatalf("unmarshal: %v\noutput: %s", err, stdout)
	}
	if parsed["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat = %v, want CycloneDX", parsed["bomFormat"])
	}
	comps, ok := parsed["components"].([]any)
	if !ok {
		t.Fatal("components should be an array")
	}
	if len(comps) != 0 {
		t.Errorf("components should be empty, got %d", len(comps))
	}
}
