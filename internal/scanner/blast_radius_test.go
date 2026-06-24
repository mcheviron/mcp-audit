package scanner

import (
	"testing"
)

func TestLinkFindings_CVEToCredentialOnSameServer(t *testing.T) {
	results := []Result{
		{
			Severity: SevCritical,
			Server:   "filesystem",
			Type:     "cve",
			Finding:  "CVE-2024-1234: buffer overflow in @modelcontextprotocol/server-filesystem",
		},
		{
			Severity: SevCritical,
			Server:   "filesystem",
			Type:     "credential",
			Finding:  "AWS access key detected in tool response",
		},
		{
			Severity: SevInfo,
			Server:   "other-server",
			Type:     "cve",
			Finding:  "CVE-2024-5678: XSS in unrelated-package",
		},
	}

	LinkFindings(results)

	if len(results[0].RelatedFindings) != 1 {
		t.Fatalf("expected 1 related finding for CVE on filesystem, got %d", len(results[0].RelatedFindings))
	}
	ref := results[0].RelatedFindings[0]
	if ref.Type != "credential" {
		t.Errorf("expected related finding type 'credential', got %q", ref.Type)
	}
	if ref.Label == "" {
		t.Error("expected non-empty label for related finding")
	}

	if len(results[2].RelatedFindings) != 0 {
		t.Errorf("expected 0 related findings for CVE on other-server, got %d", len(results[2].RelatedFindings))
	}

	if len(results[1].RelatedFindings) != 0 {
		t.Errorf("expected 0 related findings for credential entry, got %d", len(results[1].RelatedFindings))
	}
}

func TestLinkFindings_NoCVEFindings(t *testing.T) {
	results := []Result{
		{
			Severity: SevCritical,
			Server:   "filesystem",
			Type:     "credential",
			Finding:  "AWS key detected",
		},
	}

	LinkFindings(results)

	for _, r := range results {
		if len(r.RelatedFindings) > 0 {
			t.Errorf("expected no related findings when no CVEs, got %d on type=%s", len(r.RelatedFindings), r.Type)
		}
	}
}

func TestComputeChains_ThreeHopChain(t *testing.T) {
	results := []Result{
		{
			Severity: SevHigh,
			Server:   "filesystem",
			Type:     "cve",
			Finding:  "CVE-2024-1234: @modelcontextprotocol/server-filesystem RCE",
		},
		{
			Severity: SevCritical,
			Server:   "filesystem",
			Type:     "credential",
			Finding:  "AWS access key detected",
		},
		{
			Severity: SevMedium,
			Server:   "filesystem",
			Type:     "analysis",
			Finding:  "tool read_file has excessive permissions",
		},
	}

	chains := ComputeChains(results, 3)

	if len(chains) == 0 {
		t.Fatal("expected at least one chain, got 0")
	}

	chain := chains[0]
	if len(chain.Hops) == 0 {
		t.Fatal("expected non-empty hops")
	}

	cveHop := chain.Hops[0]
	if cveHop.Type != "cve" {
		t.Errorf("expected first hop type 'cve', got %q", cveHop.Type)
	}

	foundTool := false
	foundCred := false
	for _, h := range chain.Hops {
		switch h.Type {
		case "tool_analysis", "analysis":
			foundTool = true
		case "credential":
			foundCred = true
		}
	}
	if !foundTool {
		t.Error("expected tool analysis hop in chain")
	}
	if !foundCred {
		t.Error("expected credential hop in chain")
	}
}

func TestComputeChains_DepthTruncation(t *testing.T) {
	results := []Result{
		{
			Severity: SevHigh,
			Server:   "filesystem",
			Type:     "cve",
			Finding:  "CVE-2024-1234: @modelcontextprotocol/server-filesystem RCE",
		},
		{
			Severity: SevCritical,
			Server:   "filesystem",
			Type:     "credential",
			Finding:  "AWS key detected",
		},
		{
			Severity: SevMedium,
			Server:   "filesystem",
			Type:     "analysis",
			Finding:  "tool read_file has excessive permissions",
		},
	}

	chains := ComputeChains(results, 1)

	if len(chains) == 0 {
		t.Fatal("expected at least one chain, got 0")
	}

	chain := chains[0]
	if len(chain.Hops) > 2 {
		t.Errorf("expected at most 2 hops with depth 1, got %d", len(chain.Hops))
	}
}

func TestComputeChains_NoCVEsProducesEmptyChains(t *testing.T) {
	results := []Result{
		{
			Severity: SevCritical,
			Server:   "filesystem",
			Type:     "credential",
			Finding:  "AWS key detected",
		},
	}

	chains := ComputeChains(results, 3)

	if len(chains) != 0 {
		t.Errorf("expected empty chains when no CVEs, got %d", len(chains))
	}
}

func TestComputeChains_MaxSeverityComputedCorrectly(t *testing.T) {
	results := []Result{
		{
			Severity: SevCritical,
			Server:   "filesystem",
			Type:     "cve",
			Finding:  "CVE-2024-9999: critical vuln in @modelcontextprotocol/server-filesystem",
		},
		{
			Severity: SevHigh,
			Server:   "filesystem",
			Type:     "credential",
			Finding:  "AWS key detected",
		},
		{
			Severity: SevMedium,
			Server:   "filesystem",
			Type:     "analysis",
			Finding:  "tool read_file has excessive permissions",
		},
	}

	chains := ComputeChains(results, 3)

	if len(chains) == 0 {
		t.Fatal("expected at least one chain")
	}

	chain := chains[0]
	if chain.MaxSeverity != SevCritical {
		t.Errorf("expected max_severity CRITICAL, got %s", chain.MaxSeverity)
	}
}
