package report

import (
	"testing"

	"github.com/mostafaelataby-cheviron/mcp-audit/internal/scanner"
)

func TestDeduplicateIdentical(t *testing.T) {
	results := []scanner.Result{
		{Severity: scanner.SevPass, Server: "srv", Type: "dynamic", Finding: "no SSRF detected for http://127.0.0.1/"},
		{Severity: scanner.SevHigh, Server: "srv", Type: "dynamic", Finding: "no SSRF detected for http://127.0.0.1/"},
	}
	deduped := Deduplicate(results)
	if len(deduped) != 1 {
		t.Fatalf("expected 1 deduped result, got %d", len(deduped))
	}
	if deduped[0].Severity != scanner.SevHigh {
		t.Errorf("expected severity HIGH, got %v", deduped[0].Severity)
	}
}

func TestDeduplicateDifferentServer(t *testing.T) {
	results := []scanner.Result{
		{Severity: scanner.SevPass, Server: "srv1", Type: "dynamic", Finding: "no SSRF detected"},
		{Severity: scanner.SevPass, Server: "srv2", Type: "dynamic", Finding: "no SSRF detected"},
	}
	deduped := Deduplicate(results)
	if len(deduped) != 2 {
		t.Fatalf("expected 2 results (different servers), got %d", len(deduped))
	}
}

func TestDeduplicateDifferentType(t *testing.T) {
	results := []scanner.Result{
		{Severity: scanner.SevPass, Server: "srv", Type: "static", Finding: "no issue"},
		{Severity: scanner.SevPass, Server: "srv", Type: "dynamic", Finding: "no issue"},
	}
	deduped := Deduplicate(results)
	if len(deduped) != 2 {
		t.Fatalf("expected 2 results (different types), got %d", len(deduped))
	}
}

func TestDeduplicateSeverityEscalation(t *testing.T) {
	results := []scanner.Result{
		{Severity: scanner.SevPass, Server: "srv", Type: "dynamic", Finding: "target probe"},
		{Severity: scanner.SevCritical, Server: "srv", Type: "dynamic", Finding: "target probe"},
	}
	deduped := Deduplicate(results)
	if len(deduped) != 1 {
		t.Fatalf("expected 1 deduped result, got %d", len(deduped))
	}
	if deduped[0].Severity != scanner.SevCritical {
		t.Errorf("expected severity CRITICAL, got %v", deduped[0].Severity)
	}
}

func TestDeduplicateMergeDetail(t *testing.T) {
	results := []scanner.Result{
		{Severity: scanner.SevHigh, Server: "srv", Type: "dynamic", Finding: "test", Detail: "detail1"},
		{Severity: scanner.SevHigh, Server: "srv", Type: "dynamic", Finding: "test", Detail: "detail2"},
	}
	deduped := Deduplicate(results)
	if len(deduped) != 1 {
		t.Fatalf("expected 1 deduped result, got %d", len(deduped))
	}
	if deduped[0].Detail != "detail1; detail2" {
		t.Errorf("expected merged detail, got %q", deduped[0].Detail)
	}
}

func TestNormalizeFinding(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Hello   World", "hello world"},
		{"  MULTIPLE   SPACES  ", "multiple spaces"},
		{"MixedCase Finding", "mixedcase finding"},
	}
	for _, tt := range tests {
		if got := normalizeFinding(tt.input); got != tt.expected {
			t.Errorf("normalizeFinding(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}
