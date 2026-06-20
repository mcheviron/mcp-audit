package main

import (
	"strings"
	"testing"

	"github.com/mostafaelataby-cheviron/mcp-audit/internal/scanner"
)

func TestAnonymizeFindings(t *testing.T) {
	results := []scanner.Result{
		{
			Severity: scanner.SevHigh,
			Server:   "my-private-server.internal",
			Type:     "probe",
			Finding:  "SSRF detected",
			Detail:   "connected to http://192.168.1.1/admin",
		},
		{
			Severity: scanner.SevInfo,
			Server:   "another-server",
			Type:     "static",
			Finding:  "typosquat detected",
			Detail:   "package foo is distance 1 from @anthropic/bar",
		},
		{
			Severity: scanner.SevPass,
			Server:   "clean-server",
			Type:     "static",
			Finding:  "no issues",
			Detail:   "",
		},
	}

	anon := anonymizeFindings(results)

	if len(anon.Findings) != 2 {
		t.Fatalf("expected 2 findings (PASS excluded), got %d", len(anon.Findings))
	}

	for _, f := range anon.Findings {
		if containsAny(f.Finding, "my-private-server.internal", "another-server", "clean-server") {
			t.Errorf("finding should not contain server name: %q", f.Finding)
		}
		if strings.Contains(f.Detail, "192.168.1.1") {
			t.Errorf("detail should not contain IP: %q", f.Detail)
		}
	}
}

func TestAnonymizeFindingsEmpty(t *testing.T) {
	anon := anonymizeFindings(nil)
	if len(anon.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(anon.Findings))
	}
}

func TestSanitizeDetailRedactsIPs(t *testing.T) {
	input := "connection from 192.168.1.1:8080"
	result := sanitizeDetail(input)
	if strings.Contains(result, "192.168.1.1") {
		t.Errorf("IP should be redacted: %q", result)
	}
	if !strings.Contains(result, "REDACTED") {
		t.Error("expected REDACTED marker for IP")
	}
}

func TestSanitizeDetailRedactsHosts(t *testing.T) {
	tests := []string{
		"connected to metadata.google.internal",
		"target was secret-server.internal",
		"redirected to evil.com",
		"resolution failed for internal-api.local",
	}
	for _, tc := range tests {
		result := sanitizeDetail(tc)
		if strings.Contains(result, ".internal") {
			t.Errorf("host should be redacted: input=%q result=%q", tc, result)
		}
		if !strings.Contains(result, "REDACTED") {
			t.Errorf("expected REDACTED in result for input=%q, got=%q", tc, result)
		}
	}
}

func TestSanitizeDetailRedactsURLs(t *testing.T) {
	input := "found at http://evil.com/path and https://secure.org/data"
	result := sanitizeDetail(input)
	if strings.Contains(result, "http://") || strings.Contains(result, "https://") {
		t.Errorf("URLs should be redacted: %q", result)
	}
}

func TestLooksLikeHost(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"example.com", true},
		{"metadata.google.internal", true},
		{"compute.internal", true},
		{"myservice.svc", true},
		{"pod.ns.svc", true},
		{"myapp.cluster.local", true},
		{"internal-api.corp", true},
		{"dev-box.lan", true},
		{"staging.lab", true},
		{"unit.test", true},
		{"machine.localhost", true},
		{"hello", false},
		{"", false},
		{"localhost", false},
	}
	for _, tc := range tests {
		if looksLikeHost(tc.input) != tc.expected {
			t.Errorf("looksLikeHost(%q): expected %v, got %v", tc.input, tc.expected, !tc.expected)
		}
	}
}

func TestLooksLikeIP(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"127.0.0.1", true},
		{"not.an.ip", false},
		{"", false},
		{"example.com", false},
	}
	for _, tc := range tests {
		if looksLikeIP(tc.input) != tc.expected {
			t.Errorf("looksLikeIP(%q): expected %v, got %v", tc.input, tc.expected, !tc.expected)
		}
	}
}

func TestLooksLikeURL(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"http://example.com", true},
		{"https://secure.org", true},
		{"ws://socket.io", true},
		{"just text", false},
		{"", false},
	}
	for _, tc := range tests {
		if looksLikeURL(tc.input) != tc.expected {
			t.Errorf("looksLikeURL(%q): expected %v, got %v", tc.input, tc.expected, !tc.expected)
		}
	}
}

func TestAnonymizeFindingsDeduplication(t *testing.T) {
	results := []scanner.Result{
		{
			Severity: scanner.SevHigh,
			Server:   "server-a",
			Type:     "probe",
			Finding:  "SSRF detected",
		},
		{
			Severity: scanner.SevHigh,
			Server:   "server-b",
			Type:     "probe",
			Finding:  "SSRF detected",
		},
	}

	anon := anonymizeFindings(results)

	if len(anon.Findings) != 1 {
		t.Errorf("expected 1 finding after dedup, got %d", len(anon.Findings))
	}
}

func TestAnonymizeFindingsRedactsIPsInFinding(t *testing.T) {
	results := []scanner.Result{
		{
			Severity: scanner.SevHigh,
			Server:   "test-server",
			Type:     "dynamic",
			Finding:  "tool \"fetch\" leaked metadata via probe to 192.168.1.1:8080",
			Detail:   "connection established to 192.168.1.1",
		},
	}

	anon := anonymizeFindings(results)

	if len(anon.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(anon.Findings))
	}
	f := anon.Findings[0]
	if strings.Contains(f.Finding, "192.168.1.1") {
		t.Errorf("IP should be redacted in Finding: %q", f.Finding)
	}
	if !strings.Contains(f.Finding, "REDACTED") {
		t.Error("expected REDACTED marker in Finding")
	}
	if strings.Contains(f.Detail, "192.168.1.1") {
		t.Errorf("IP should be redacted in Detail: %q", f.Detail)
	}
}

func TestAnonymizeFindingsRedactsHostnamesInFinding(t *testing.T) {
	results := []scanner.Result{
		{
			Severity: scanner.SevHigh,
			Server:   "test-server",
			Type:     "dynamic",
			Finding:  "redirect to metadata.internal detected",
		},
	}

	anon := anonymizeFindings(results)

	if len(anon.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(anon.Findings))
	}
	f := anon.Findings[0]
	if strings.Contains(f.Finding, "metadata.internal") {
		t.Errorf("hostname should be redacted in Finding: %q", f.Finding)
	}
	if !strings.Contains(f.Finding, "REDACTED") {
		t.Error("expected REDACTED marker in Finding")
	}
}

func TestAnonymizeFindingsRedactsNewTLDs(t *testing.T) {
	results := []scanner.Result{
		{
			Severity: scanner.SevLow,
			Server:   "srv",
			Type:     "dynamic",
			Finding:  "target svc-name.ns.svc responded",
			Detail:   "host pod.cluster.local:8080 accessed",
		},
	}

	anon := anonymizeFindings(results)

	if len(anon.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(anon.Findings))
	}
	f := anon.Findings[0]
	if strings.Contains(f.Finding, ".svc") {
		t.Errorf(".svc TLD should be redacted in Finding: %q", f.Finding)
	}
	if strings.Contains(f.Detail, ".cluster.local") {
		t.Errorf(".cluster.local TLD should be redacted in Detail: %q", f.Detail)
	}
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
