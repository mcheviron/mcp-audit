package scanner

import (
	"testing"
)

func TestMapToCompliance_CredentialToSOC2(t *testing.T) {
	controls := MapToCompliance("credential", SevCritical)

	foundSOC2 := false
	for _, c := range controls {
		if c.Framework == "SOC 2" && c.Control == "CC6.1" {
			foundSOC2 = true
		}
	}
	if !foundSOC2 {
		t.Error("expected credential finding to map to SOC 2 CC6.1")
	}
}

func TestMapToCompliance_InjectionToOWASP(t *testing.T) {
	controls := MapToCompliance("prompt_injection", SevHigh)

	foundOWASP := false
	for _, c := range controls {
		if c.Framework == "OWASP LLM Top-10" && c.Control == "LLM01: Prompt Injection" {
			foundOWASP = true
		}
	}
	if !foundOWASP {
		t.Error("expected prompt_injection finding to map to OWASP LLM01")
	}
}

func TestMapToCompliance_UnknownTypeEmptyMapping(t *testing.T) {
	controls := MapToCompliance("unknown_finding_type", SevInfo)

	if len(controls) != 0 {
		t.Errorf("expected empty mapping for unknown type, got %d controls", len(controls))
	}
}

func TestMapToCompliance_AllFrameworkShortNames(t *testing.T) {
	names := GetAllFrameworkShortNames()

	expected := map[string]bool{
		"soc2":        false,
		"nist-ai-rmf": false,
		"owasp-llm":   false,
		"mitre-atlas": false,
		"eu-ai-act":   false,
	}
	for _, n := range names {
		if _, ok := expected[n]; ok {
			expected[n] = true
		}
	}
	for name, found := range expected {
		if !found {
			t.Errorf("expected framework %q not found in GetAllFrameworkShortNames", name)
		}
	}
}

func TestMapResultsToCompliance_PopulatesTags(t *testing.T) {
	results := []Result{
		{
			Severity: SevCritical,
			Server:   "test-srv",
			Type:     "credential",
			Finding:  "AWS key detected",
		},
		{
			Severity: SevHigh,
			Server:   "test-srv",
			Type:     "cve",
			Finding:  "CVE-2024-0001",
		},
	}

	mapped := MapResultsToCompliance(results)

	if len(mapped[0].Compliance) == 0 {
		t.Error("expected compliance tags on credential finding")
	}

	hasSOC2 := false
	for _, tag := range mapped[0].Compliance {
		if tag.Framework == "SOC 2" {
			hasSOC2 = true
		}
	}
	if !hasSOC2 {
		t.Error("expected SOC 2 compliance tag on credential finding")
	}

	if len(mapped[1].Compliance) == 0 {
		t.Error("expected compliance tags on CVE finding")
	}
}
