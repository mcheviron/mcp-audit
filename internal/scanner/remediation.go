package scanner

import "strings"

func PopulateRemediation(r *Result) {
	switch {
	case r.Severity == SevCritical && r.Type == FindingTypeDynamic:
		r.Remediation = "Configure the MCP server to validate and sanitize all user-supplied URLs. " +
			"Implement an allowlist of permitted outbound destinations. " +
			"Never pass tool arguments directly to HTTP clients without validation."
	case r.Severity == SevHigh && r.Type == FindingTypeDynamic:
		if strings.Contains(r.Finding, "redirect") {
			r.Remediation = "Validate and sanitize all redirect targets. " +
				"Implement a redirect allowlist and reject redirects to internal or untrusted hosts."
		} else {
			r.Remediation = "Review the MCP server's response handling. " +
				"Implement output sanitization to prevent leakage of internal content."
		}
	case r.Severity == SevHigh && r.Type == FindingTypeStatic:
		r.Remediation = "Review the tool's capabilities and ensure least-privilege principle is applied. " +
			"Restrict tool access to only necessary resources."
	case r.Severity == SevMedium:
		r.Remediation = "Investigate the finding and evaluate whether the behavior is expected. " +
			"Consider adding network-level restrictions or input validation."
	case r.Severity == SevLow:
		r.Remediation = "Review and consider applying the principle of least privilege. " +
			"Verify that the behavior is documented and intentional."
	case r.Severity == SevInfo && r.Type == FindingTypeStatic:
		if strings.Contains(r.Finding, "typosquat") || strings.Contains(r.Finding, "distance") {
			r.Remediation = "Verify the package name is correct. " +
				"Consider adding it to the trust config trusted list if legitimate, " +
				"or the blocked list if malicious."
		} else {
			r.Remediation = "Review the finding for awareness. No immediate action required."
		}
	case r.Type == FindingTypeCVE && r.Severity >= SevHigh:
		r.Remediation = "Update the affected package to a patched version immediately. " +
			"See the CVE details for specific fix versions and workarounds."
	case r.Type == FindingTypeCVE && r.Severity >= SevMedium:
		r.Remediation = "Review the CVE and schedule a package update. " +
			"Evaluate whether the vulnerability is exploitable in your deployment context."
	case r.Type == FindingTypeCVE:
		r.Remediation = "Monitor for updates and apply patches when available. " +
			"Evaluate impact based on your deployment scenario."
	case r.Severity == SevPass:
	default:
		r.Remediation = "Review the finding and take appropriate action based on your security policies."
	}
}
