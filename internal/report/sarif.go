package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/mostafaelataby-cheviron/mcp-audit/internal/scanner"
)

type sarifLog struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool    tool     `json:"tool"`
	Results []result `json:"results"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type result struct {
	RuleID    string  `json:"ruleId"`
	Level     string  `json:"level"`
	Message   message `json:"message"`
	Locations []loc   `json:"locations"`
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

func writeSARIF(w io.Writer, results []scanner.Result) error {
	var sarifResults []result
	for _, r := range results {
		if r.Severity == scanner.SevPass {
			continue
		}
		sarifResults = append(sarifResults, result{
			RuleID: fmt.Sprintf("mcp-audit/%s-%s", r.Type, stringsToLower(r.Severity.String())),
			Level:  severityToSARIF(r.Severity),
			Message: message{
				Text: fmt.Sprintf("[%s] %s: %s", r.Severity, r.Server, r.Finding),
			},
			Locations: []loc{{
				PhysicalLocation: physLoc{
					ArtifactLocation: artifactLoc{
						URI: r.Server,
					},
				},
			}},
		})
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []run{{
			Tool: tool{
				Driver: driver{
					Name:    "mcp-audit",
					Version: "0.1.0",
				},
			},
			Results: sarifResults,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func stringsToLower(s string) string {
	return strings.ToLower(s)
}
