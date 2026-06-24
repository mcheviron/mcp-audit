package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempPolicy(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write temp policy: %v", err)
	}
	return path
}

func buildTestBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "mcp-audit")
	pkgDir := filepath.Join("github.com", "mostafaelataby-cheviron", "mcp-audit", "cmd", "mcp-audit")
	cmd := exec.Command("go", "build", "-o", bin, pkgDir)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build: %v", err)
	}
	return bin
}

func TestValidateSubcommandValidPolicy(t *testing.T) {
	yaml := `
rules:
  - action: allow
    priority: 10
    method: tools/list
  - action: deny
    priority: 20
    method: tools/call
    tool: dangerous
`
	path := writeTempPolicy(t, yaml)
	bin := buildTestBinary(t)

	out, err := exec.Command(bin, "proxy", "policy", "validate", path).CombinedOutput()
	if err != nil {
		t.Fatalf("expected exit 0, got: %v\noutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "Policy valid") {
		t.Errorf("expected 'Policy valid' in output, got: %s", string(out))
	}
}

func TestValidateSubcommandInvalidPolicy(t *testing.T) {
	yaml := `
rules:
  - action: block
    priority: 10
    method: tools/list
`
	path := writeTempPolicy(t, yaml)
	bin := buildTestBinary(t)

	out, err := exec.Command(bin, "proxy", "policy", "validate", path).CombinedOutput()
	if err == nil {
		t.Fatal("expected exit non-zero for invalid policy")
	}
	if !strings.Contains(string(out), "Policy validation failed") {
		t.Errorf("expected 'Policy validation failed' in output, got: %s", string(out))
	}
}
