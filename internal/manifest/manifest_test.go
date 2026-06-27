package manifest

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestBuildNonEmptyFields(t *testing.T) {
	m := Build()
	if m.Version == "" {
		t.Error("expected non-empty version")
	}
	if m.Commit == "" {
		t.Error("expected non-empty commit")
	}
	if m.BuildDate == "" {
		t.Error("expected non-empty build_date")
	}
	if m.GoVersion == "" {
		t.Error("expected non-empty go_version")
	}
	if m.SchemaJSON == "" {
		t.Error("expected non-empty schema_json")
	}
	if m.SchemaSARIF == "" {
		t.Error("expected non-empty schema_sarif")
	}
}

func TestWriteJSONContainsAllRequiredKeys(t *testing.T) {
	m := Build()
	var buf bytes.Buffer
	if err := m.WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	required := []string{
		"version",
		"commit",
		"build_date",
		"go_version",
		"trust_list_sha256",
		"probes_list_sha256",
		"schema_json",
		"schema_sarif",
	}
	for _, key := range required {
		if _, ok := parsed[key]; !ok {
			t.Errorf("missing required key %q in JSON output", key)
		}
	}
	if len(parsed) != len(required) {
		var extra []string
		for k := range parsed {
			if !slices.Contains(required, k) {
				extra = append(extra, k)
			}
		}
		t.Errorf("unexpected extra keys in JSON output: %v", extra)
	}
}

func TestWriteJSONDeterministic(t *testing.T) {
	m1 := Build()
	var buf1, buf2 bytes.Buffer
	if err := m1.WriteJSON(&buf1); err != nil {
		t.Fatalf("first WriteJSON failed: %v", err)
	}
	m2 := Build()
	if err := m2.WriteJSON(&buf2); err != nil {
		t.Fatalf("second WriteJSON failed: %v", err)
	}
	if !bytes.Equal(buf1.Bytes(), buf2.Bytes()) {
		t.Errorf("WriteJSON output is not deterministic across calls\nfirst:  %s\nsecond: %s",
			buf1.String(), buf2.String())
	}
}

func TestSHA256HashesAreHex(t *testing.T) {
	m := Build()
	if got := m.TrustListSHA256; len(got) != 64 {
		t.Errorf("trust_list_sha256 should be 64 hex chars, got %d (%q)", len(got), got)
	}
	if got := m.ProbesListSHA256; len(got) != 64 {
		t.Errorf("probes_list_sha256 should be 64 hex chars, got %d (%q)", len(got), got)
	}
	for _, c := range m.TrustListSHA256 {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("trust_list_sha256 contains non-hex char %q", c)
			break
		}
	}
	for _, c := range m.ProbesListSHA256 {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("probes_list_sha256 contains non-hex char %q", c)
			break
		}
	}
}

func TestWriteTextContainsVersion(t *testing.T) {
	m := Build()
	var buf bytes.Buffer
	if err := m.WriteText(&buf); err != nil {
		t.Fatalf("WriteText failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, m.Version) {
		t.Errorf("WriteText output should contain version %q, got:\n%s", m.Version, out)
	}
	firstLine := strings.SplitN(out, "\n", 2)[0]
	if !strings.HasPrefix(firstLine, "version") {
		t.Errorf("first line of text output should start with 'version', got %q", firstLine)
	}
}
