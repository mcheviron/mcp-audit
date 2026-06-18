package scanner

import (
	"testing"
)

func TestPopulateRemediationCriticalSSRF(t *testing.T) {
	r := &Result{Severity: SevCritical, Type: "dynamic", Finding: "AWS credentials exposed via http://127.0.0.1/"}
	PopulateRemediation(r)
	if r.Remediation == "" {
		t.Error("critical SSRF should have remediation")
	}
}

func TestPopulateRemediationHighRedirect(t *testing.T) {
	r := &Result{Severity: SevHigh, Type: "dynamic", Finding: "open redirect to http://192.168.1.1/ (status 302)"}
	PopulateRemediation(r)
	if r.Remediation == "" {
		t.Error("high redirect should have remediation")
	}
}

func TestPopulateRemediationHighStatic(t *testing.T) {
	r := &Result{Severity: SevHigh, Type: "static", Finding: "tool \"exec\" capabilities: shell"}
	PopulateRemediation(r)
	if r.Remediation == "" {
		t.Error("high static should have remediation")
	}
}

func TestPopulateRemediationMedium(t *testing.T) {
	r := &Result{Severity: SevMedium, Type: "dynamic", Finding: "connection failed"}
	PopulateRemediation(r)
	if r.Remediation == "" {
		t.Error("medium should have remediation")
	}
}

func TestPopulateRemediationLow(t *testing.T) {
	r := &Result{Severity: SevLow, Type: "static", Finding: "some low finding"}
	PopulateRemediation(r)
	if r.Remediation == "" {
		t.Error("low should have remediation")
	}
}

func TestPopulateRemediationInfoTyposquat(t *testing.T) {
	r := &Result{Severity: SevInfo, Type: "static", Finding: "potential typosquat: \"mcp-audt\" is distance 1 from trusted package \"mcp-audit\""}
	PopulateRemediation(r)
	if r.Remediation == "" {
		t.Error("typosquat info should have remediation")
	}
}

func TestPopulateRemediationPass(t *testing.T) {
	r := &Result{Severity: SevPass, Type: "dynamic", Finding: "no SSRF detected"}
	PopulateRemediation(r)
	if r.Remediation != "" {
		t.Error("pass should have no remediation")
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  Severity
	}{
		{"PASS", SevPass},
		{"INFO", SevInfo},
		{"LOW", SevLow},
		{"MEDIUM", SevMedium},
		{"HIGH", SevHigh},
		{"CRITICAL", SevCritical},
		{"invalid", SevPass},
	}
	for _, tt := range tests {
		if got := ParseSeverity(tt.input); got != tt.want {
			t.Errorf("ParseSeverity(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
