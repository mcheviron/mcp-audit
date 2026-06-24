package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/mcheviron/mcp-audit/internal/scanner"
)

type sarifLog struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool                     tool                 `json:"tool"`
	Results                  []result             `json:"results"`
	VersionControlProvenance []versionControlProv `json:"versionControlProvenance,omitempty"`
}

type versionControlProv struct {
	RepositoryURI string `json:"repositoryUri"`
	Branch        string `json:"branch,omitempty"`
	RevisionID    string `json:"revisionId,omitempty"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name    string                `json:"name"`
	Version string                `json:"version"`
	Rules   []reportingDescriptor `json:"rules,omitempty"`
	Taxa    []taxa                `json:"taxa,omitempty"`
}

type reportingDescriptor struct {
	ID            string                      `json:"id"`
	Name          string                      `json:"name"`
	HelpURI       string                      `json:"helpUri"`
	Relationships []toolComponentRelationship `json:"relationships,omitempty"`
}

type toolComponentRelationship struct {
	Target targetRef `json:"target"`
	Kinds  []string  `json:"kinds"`
}

type targetRef struct {
	ID            string `json:"id"`
	GUID          string `json:"guid"`
	ToolComponent string `json:"toolComponent"`
}

type taxa struct {
	ID               string      `json:"id"`
	Name             string      `json:"name"`
	ShortDescription description `json:"shortDescription"`
}

type description struct {
	Text string `json:"text"`
}

type result struct {
	RuleID     string            `json:"ruleId"`
	Level      string            `json:"level"`
	Message    message           `json:"message"`
	Locations  []loc             `json:"locations"`
	Rank       float64           `json:"rank,omitempty"`
	Properties *resultProperties `json:"properties,omitempty"`
}

type resultProperties struct {
	SecurityScore   float64                 `json:"securityScore,omitempty"`
	TrustScore      float64                 `json:"trustScore,omitempty"`
	RelatedFindings []scanner.FindingRef    `json:"relatedFindings,omitempty"`
	ComplianceTags  []scanner.ComplianceTag `json:"complianceTags,omitempty"`
}

type message struct {
	Text string `json:"text"`
}

type loc struct {
	PhysicalLocation physLoc `json:"physicalLocation"`
}

type physLoc struct {
	ArtifactLocation artifactLoc `json:"artifactLocation"`
}

type artifactLoc struct {
	URI string `json:"uri"`
}

func severityToSARIF(s scanner.Severity) string {
	switch s {
	case scanner.SevCritical, scanner.SevHigh:
		return "error"
	case scanner.SevMedium:
		return "warning"
	default:
		return "note"
	}
}

func sarifResultsFromFindings(results []scanner.Result) []result {
	out := make([]result, 0, len(results))
	for _, r := range results {
		uri := r.Server
		if r.ConfigPath != "" {
			uri = r.ConfigPath
		}
		level := severityToSARIF(r.Severity)
		ruleID := fmt.Sprintf("mcp-audit/%s-%s", r.Type,
			strings.ToLower(r.Severity.String()))
		sr := result{
			RuleID: ruleID,
			Level:  level,
			Message: message{
				Text: sarifMessageText(r),
			},
			Locations: []loc{{
				PhysicalLocation: physLoc{
					ArtifactLocation: artifactLoc{
						URI: uri,
					},
				},
			}},
		}
		if r.Score > 0 || r.TrustScore != 0 {
			sr.Rank = 100 - r.Score
			sr.Properties = &resultProperties{
				SecurityScore: r.Score,
				TrustScore:    r.TrustScore,
			}
		}
		if len(r.RelatedFindings) > 0 || len(r.Compliance) > 0 {
			if sr.Properties == nil {
				sr.Properties = &resultProperties{}
			}
			sr.Properties.RelatedFindings = r.RelatedFindings
			sr.Properties.ComplianceTags = r.Compliance
		}
		out = append(out, sr)
	}
	return out
}

func sarifReportingRules() []reportingDescriptor {
	cweRel := func(cwe string) []toolComponentRelationship {
		return []toolComponentRelationship{{
			Target: targetRef{ID: cwe, GUID: cwe, ToolComponent: "cwe"},
			Kinds:  []string{"relevant"},
		}}
	}
	return []reportingDescriptor{
		{ID: "mcp-audit/dynamic-critical", Name: "SSRF Critical",
			HelpURI:       "https://owasp.org/www-project-mcp-top-10/",
			Relationships: cweRel("CWE-918")},
		{ID: "mcp-audit/dynamic-high", Name: "Information Exposure",
			HelpURI:       "https://owasp.org/www-project-mcp-top-10/",
			Relationships: cweRel("CWE-200")},
		{ID: "mcp-audit/static-info", Name: "Typosquat Detection",
			HelpURI:       "https://owasp.org/www-project-mcp-top-10/",
			Relationships: cweRel("CWE-350")},
		{ID: "mcp-audit/static-critical", Name: "Malicious Code",
			HelpURI:       "https://owasp.org/www-project-mcp-top-10/",
			Relationships: cweRel("CWE-506")},
		{ID: "mcp-audit/cve-critical", Name: "CVE Critical",
			HelpURI:       "https://owasp.org/www-project-mcp-top-10/",
			Relationships: cweRel("CWE-937")},
		{ID: "mcp-audit/cve-high", Name: "CVE High Severity",
			HelpURI:       "https://owasp.org/www-project-mcp-top-10/",
			Relationships: cweRel("CWE-937")},
		{ID: "mcp-audit/cve-medium", Name: "CVE Medium Severity",
			HelpURI:       "https://owasp.org/www-project-mcp-top-10/",
			Relationships: cweRel("CWE-937")},
		{ID: "mcp-audit/cve-low", Name: "CVE Low Severity",
			HelpURI:       "https://owasp.org/www-project-mcp-top-10/",
			Relationships: cweRel("CWE-937")},
	}
}

func sarifTaxa() []taxa {
	desc := func(s string) description { return description{Text: s} }
	return []taxa{
		{ID: "CWE-918", Name: "CWE-918", ShortDescription: desc("Server-Side Request Forgery (SSRF)")},
		{ID: "CWE-200", Name: "CWE-200", ShortDescription: desc("Exposure of Sensitive Information")},
		{ID: "CWE-350", Name: "CWE-350", ShortDescription: desc("Reliance on Reverse DNS Resolution")},
		{ID: "CWE-506", Name: "CWE-506", ShortDescription: desc("Embedded Malicious Code")},
		{ID: "CWE-937", Name: "CWE-937", ShortDescription: desc("Using Components with Known Vulnerabilities")},
	}
}

func writeSARIF(w io.Writer, results []scanner.Result, ci *CIInfo) error {
	r := run{
		Tool: tool{
			Driver: driver{
				Name:    "mcp-audit",
				Version: "0.1.0",
				Rules:   sarifReportingRules(),
				Taxa:    sarifTaxa(),
			},
		},
		Results: sarifResultsFromFindings(results),
	}
	if ci != nil && ci.Enabled && ci.Repo != "" {
		prov := versionControlProv{
			RepositoryURI: ci.Repo,
		}
		if ci.Branch != "" {
			prov.Branch = ci.Branch
		}
		if ci.CommitSHA != "" {
			prov.RevisionID = ci.CommitSHA
		}
		r.VersionControlProvenance = []versionControlProv{prov}
	}
	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs:    []run{r},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func sarifMessageText(r scanner.Result) string {
	t := fmt.Sprintf("[%s] %s: %s", r.Severity, r.Server, r.Finding)
	if r.Remediation != "" {
		t += " | Remediation: " + r.Remediation
	}
	return t
}
