package report

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mcheviron/mcp-audit/internal/scanner"
)

func TestExportEvidence_HMACChainIntegrity(t *testing.T) {
	results := []scanner.Result{
		{
			Severity: scanner.SevCritical,
			Server:   "filesystem",
			Type:     "cve",
			Finding:  "CVE-2024-1234: buffer overflow",
			Detail:   "CVSS 9.8",
		},
		{
			Severity: scanner.SevHigh,
			Server:   "filesystem",
			Type:     "credential",
			Finding:  "AWS key detected",
		},
	}

	key := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	tmpDir := t.TempDir()
	evidencePath := filepath.Join(tmpDir, "evidence.json")

	err := ExportEvidence(evidencePath, key, results, nil)
	if err != nil {
		t.Fatalf("ExportEvidence failed: %v", err)
	}

	valid, err := VerifyEvidenceBundle(evidencePath, key)
	if err != nil {
		t.Fatalf("VerifyEvidenceBundle failed: %v", err)
	}
	if !valid {
		t.Error("expected HMAC chain to verify with same key")
	}
}

func TestExportEvidence_DifferentKeyFails(t *testing.T) {
	results := []scanner.Result{
		{
			Severity: scanner.SevHigh,
			Server:   "test-srv",
			Type:     "cve",
			Finding:  "CVE-2024-5678",
		},
	}

	key1 := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	key2 := "ffeeddccbbaa00998877665544332211ffeeddccbbaa00998877665544332211"
	tmpDir := t.TempDir()
	evidencePath := filepath.Join(tmpDir, "evidence.json")

	err := ExportEvidence(evidencePath, key1, results, nil)
	if err != nil {
		t.Fatalf("ExportEvidence failed: %v", err)
	}

	valid, err := VerifyEvidenceBundle(evidencePath, key2)
	if err != nil {
		t.Fatalf("VerifyEvidenceBundle failed: %v", err)
	}
	if valid {
		t.Error("expected HMAC chain to fail with different key")
	}
}

func TestExportEvidence_FileWritten(t *testing.T) {
	results := []scanner.Result{
		{
			Severity: scanner.SevInfo,
			Server:   "test-srv",
			Type:     "cve",
			Finding:  "CVE-2024-0000",
		},
	}

	key := "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe"
	tmpDir := t.TempDir()
	evidencePath := filepath.Join(tmpDir, "evidence.json")

	err := ExportEvidence(evidencePath, key, results, nil)
	if err != nil {
		t.Fatalf("ExportEvidence failed: %v", err)
	}

	data, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatalf("read evidence file: %v", err)
	}
	if len(data) == 0 {
		t.Error("evidence file is empty")
	}
}

func TestExportEvidence_InvalidKey(t *testing.T) {
	results := []scanner.Result{{}}

	tmpDir := t.TempDir()
	evidencePath := filepath.Join(tmpDir, "evidence.json")

	err := ExportEvidence(evidencePath, "not-hex", results, nil)
	if err == nil {
		t.Error("expected error for invalid hex key")
	}
}
