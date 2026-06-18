package scanner

import "strings"

func PopulateRemediation(r *Result) {
	switch {
	case r.Severity == SevCritical && r.Type == "dynamic":
		r.Remediation = "Configure the MCP server to validate and sanitize all user-supplied URLs. " +
			"Implement an allowlist of permitted outbound destinations. " +
			"Never pass tool arguments directly to HTTP clients without validation."
	case r.Severity == SevHigh && r.Type == "dynamic":
		if strings.Contains(r.Finding, "redirect") {
			r.Remediation = "Validate and sanitize all redirect targets. " +
				"Implement a redirect allowlist and reject redirects to internal or untrusted hosts."
		} else {
			r.Remediation = "Review the MCP server's response handling. " +
				"Implement output sanitization to prevent leakage of internal content."
		}
	case r.Severity == SevHigh && r.Type == "static":
		r.Remediation = "Review the tool's capabilities and ensure least-privilege principle is applied. " +
			"Restrict tool access to only necessary resources."
	case r.Severity == SevMedium:
		r.Remediation = "Investigate the finding and evaluate whether the behavior is expected. " +
			"Consider adding network-level restrictions or input validation."
	case r.Severity == SevLow:
		r.Remediation = "Review and consider applying the principle of least privilege. " +
			"Verify that the behavior is documented and intentional."
	case r.Severity == SevInfo && r.Type == "static":
		if strings.Contains(r.Finding, "typosquat") || strings.Contains(r.Finding, "distance") {
			r.Remediation = "Verify the package name is correct. " +
				"Consider adding it to the trust config trusted list if legitimate, " +
				"or the blocked list if malicious."
		} else {
			r.Remediation = "Review the finding for awareness. No immediate action required."
		}
	case r.Severity == SevPass:
	default:
		r.Remediation = "Review the finding and take appropriate action based on your security policies."
	}
}
