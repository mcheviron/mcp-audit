package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSBOMSubcommandCycloneDXJSON(t *testing.T) {
	home := t.TempDir()
	claudeCfg := `{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/tmp"]}}}`
	writeClaudeConfig(t, home, claudeCfg)

	bin := buildTestBinary(t)
	out, err := exec.Command(bin, "sbom", "--config-root", home).CombinedOutput()
	if err != nil {
		t.Fatalf("sbom failed: %v\n%s", err, out)
	}

	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("unmarshal: %v\noutput: %s", err, out)
	}
	if parsed["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat = %v, want CycloneDX", parsed["bomFormat"])
	}
	if parsed["specVersion"] != "1.6" {
		t.Errorf("specVersion = %v, want 1.6", parsed["specVersion"])
	}
}

func TestSBOMSubcommandSPDXJSON(t *testing.T) {
	home := t.TempDir()
	claudeCfg := `{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/tmp"]}}}`
	writeClaudeConfig(t, home, claudeCfg)

	bin := buildTestBinary(t)
	out, err := exec.Command(bin, "sbom", "--format", "spdx-json", "--config-root", home).CombinedOutput()
	if err != nil {
		t.Fatalf("sbom failed: %v\n%s", err, out)
	}

	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("unmarshal: %v\noutput: %s", err, out)
	}
	if parsed["spdxVersion"] != "SPDX-2.3" {
		t.Errorf("spdxVersion = %v, want SPDX-2.3", parsed["spdxVersion"])
	}
}

func TestSBOMSubcommandOutputFile(t *testing.T) {
	home := t.TempDir()
	claudeCfg := `{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/tmp"]}}}`
	writeClaudeConfig(t, home, claudeCfg)

	outPath := filepath.Join(home, "test-sbom.json")
	bin := buildTestBinary(t)
	out, err := exec.Command(bin, "sbom", "--output", outPath, "--config-root", home).CombinedOutput()
	if err != nil {
		t.Fatalf("sbom failed: %v\n%s", err, out)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat = %v, want CycloneDX", parsed["bomFormat"])
	}
}

func TestSBOMSubcommandSPDXTag(t *testing.T) {
	home := t.TempDir()
	claudeCfg := `{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/tmp"]}}}`
	writeClaudeConfig(t, home, claudeCfg)

	bin := buildTestBinary(t)
	out, err := exec.Command(bin, "sbom", "--format", "spdx-tag", "--config-root", home).CombinedOutput()
	if err != nil {
		t.Fatalf("sbom failed: %v\n%s", err, out)
	}

	if !strings.Contains(string(out), "SPDXVersion: SPDX-2.3") {
		t.Errorf("output should contain SPDXVersion: SPDX-2.3\n%s", out)
	}
	if !strings.Contains(string(out), "PackageName:") {
		t.Errorf("output should contain PackageName:\n%s", out)
	}
}

func TestSBOMSubcommandCycloneDXXML(t *testing.T) {
	home := t.TempDir()
	claudeCfg := `{"mcpServers":{"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/tmp"]}}}`
	writeClaudeConfig(t, home, claudeCfg)

	bin := buildTestBinary(t)
	out, err := exec.Command(bin, "sbom", "--format", "cyclonedx-xml", "--config-root", home).CombinedOutput()
	if err != nil {
		t.Fatalf("sbom failed: %v\n%s", err, out)
	}

	if !strings.Contains(string(out), "cyclonedx.org") {
		t.Errorf("XML output should contain cyclonedx.org namespace\n%s", out)
	}
}

func writeClaudeConfig(t *testing.T, home, content string) {
	t.Helper()
	dir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(content), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
}
