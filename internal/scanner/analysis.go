package scanner

import (
	"fmt"
	"regexp"

	"github.com/mcheviron/mcp-audit/internal/config"
)

var AwsKeyPattern = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)

var GcpTokenPattern = regexp.MustCompile(`(?i)"access_token"\s*:\s*"ya29\.`)

var MetadataPattern = regexp.MustCompile(
	`(?i)(ami-id|instance-id|public-keys|security-groups|service-accounts|access_token|privateKey)`,
)

var InternalBodyPattern = regexp.MustCompile(
	`(?i)(internal|admin|localhost|127\.0\.0\.1|192\.168\.|10\.\d+\.|172\.(1[6-9]|2\d|3[01])\.)`,
)

var RedactPatterns = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`(?i)ya29\.[0-9a-z_-]+`),
	regexp.MustCompile(`(?i)"access_token"\s*:\s*"[^"]+"`),
	regexp.MustCompile(`(?i)"privateKey"\s*:\s*"[^"]+"`),
	regexp.MustCompile(`(?i)-----BEGIN (RSA |EC )?PRIVATE KEY-----[\s\S]*?-----END (RSA |EC )?PRIVATE KEY-----`),
}

func redactDetail(body string) string {
	for _, p := range RedactPatterns {
		body = p.ReplaceAllString(body, "[REDACTED]")
	}
	if len(body) > 200 {
		return body[:200] + "..."
	}
	return body
}

func analyzeProbeResult(result probeResult, srv config.ServerEntry) Result {
	if result.err != nil {
		return Result{
			Severity: SevMedium,
			Server:   srv.Name,
			Type:     FindingTypeDynamic,
			Finding:  fmt.Sprintf("connection to %s failed: %v", result.target, result.err),
		}
	}

	if result.redirect != "" {
		sev := SevHigh
		if result.body == "" && result.status >= 300 {
			sev = SevLow
		}
		return Result{
			Severity: sev,
			Server:   srv.Name,
			Type:     FindingTypeDynamic,
			Finding:  fmt.Sprintf("open redirect to %s (status %d)", result.redirect, result.status),
		}
	}

	a := assessBody(result.body, result.contentType)

	if result.status >= 200 && result.status < 300 {
		if a.score > 0.7 {
			if r := checkCriticalFromAssessment(result, srv, a); r != nil {
				return *r
			}
		}

		if r, ok := classifyAnalysisPath(result, srv, a); ok {
			return r
		}
	}

	if result.status >= 400 && a.class == ResponseError {
		return Result{
			Severity: SevPass, Server: srv.Name, Type: "dynamic",
			Finding: fmt.Sprintf("error response from %s (status %d, class=error)",
				result.target, result.status),
		}
	}

	return passResult(srv, result)
}

func classifyAnalysisPath(result probeResult, srv config.ServerEntry, a bodyAssessment) (Result, bool) {
	if a.class == ResponseError {
		return Result{
			Severity: SevPass, Server: srv.Name, Type: "dynamic",
			Finding: fmt.Sprintf("error response from %s (status %d, class=%s)",
				result.target, result.status, a.class),
		}, true
	}

	if a.band == "suspicious" && a.score > 0.3 {
		return Result{
			Severity: SevHigh, Server: srv.Name, Type: "dynamic",
			Finding: fmt.Sprintf(
				"low-entropy suspicious response via %s (entropy=%.2f, band=%s, score=%.2f)",
				result.target, a.entropy, a.band, a.score),
			Detail: redactDetail(result.body)}, true
	}

	if a.class == ResponseMetadata {
		return Result{
			Severity: SevMedium, Server: srv.Name, Type: "dynamic",
			Finding: fmt.Sprintf("metadata response via %s (class=%s, score=%.2f)",
				result.target, a.class, a.score),
		}, true
	}

	if a.class == ResponseBinary {
		return Result{
			Severity: SevPass, Server: srv.Name, Type: "dynamic",
			Finding: fmt.Sprintf("binary response from %s (status %d, entropy=%.2f)",
				result.target, result.status, a.entropy),
		}, true
	}

	if a.score < 0.3 {
		return Result{
			Severity: SevPass, Server: srv.Name, Type: "dynamic",
			Finding: fmt.Sprintf("low-suspicion response from %s (status %d, score=%.2f)",
				result.target, result.status, a.score),
		}, true
	}

	return Result{}, false
}

func checkCriticalFromAssessment(result probeResult, srv config.ServerEntry, a bodyAssessment) *Result {
	if a.containsAwsKey {
		return &Result{
			Severity: SevCritical,
			Server:   srv.Name,
			Type:     FindingTypeDynamic,
			Finding:  fmt.Sprintf("AWS credentials exposed via %s", result.target),
			Detail:   redactDetail(result.body),
		}
	}
	if a.containsGcpToken {
		return &Result{
			Severity: SevCritical,
			Server:   srv.Name,
			Type:     FindingTypeDynamic,
			Finding:  fmt.Sprintf("GCP access token exposed via %s", result.target),
			Detail:   redactDetail(result.body),
		}
	}
	if a.containsMetadata {
		return &Result{
			Severity: SevCritical,
			Server:   srv.Name,
			Type:     FindingTypeDynamic,
			Finding:  fmt.Sprintf("cloud metadata exposed via %s", result.target),
			Detail:   redactDetail(result.body),
		}
	}
	if a.containsInternal {
		return &Result{
			Severity: SevHigh,
			Server:   srv.Name,
			Type:     FindingTypeDynamic,
			Finding: fmt.Sprintf(
				"internal content returned via %s (status %d, %d bytes)",
				result.target, result.status, len(result.body),
			),
		}
	}
	return nil
}

func passResult(srv config.ServerEntry, result probeResult) Result {
	return Result{
		Severity: SevPass,
		Server:   srv.Name,
		Type:     FindingTypeDynamic,
		Finding:  fmt.Sprintf("no SSRF detected for %s (status %d)", result.target, result.status),
	}
}
