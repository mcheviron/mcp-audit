package report

import (
	"encoding/json"
	"io"
	"time"

	"github.com/mcheviron/mcp-audit/internal/scanner"
)

type jsonOutput struct {
	Tool              string                    `json:"tool"`
	Version           string                    `json:"version"`
	ScanTime          string                    `json:"scan_time"`
	Summary           jsonSummary               `json:"summary"`
	Findings          []jsonEntry               `json:"findings"`
	Scores            []jsonScore               `json:"scores,omitempty"`
	BlastRadiusChains []jsonChain               `json:"blastRadiusChains,omitempty"`
	ComplianceSummary map[string]map[string]int `json:"compliance_summary,omitempty"`
}

type jsonChain struct {
	Hops        []scanner.ChainHop `json:"hops"`
	MaxSeverity string             `json:"max_severity"`
	Truncated   bool               `json:"truncated"`
}

type jsonSummary struct {
	Critical       int `json:"critical"`
	High           int `json:"high"`
	Medium         int `json:"medium"`
	Low            int `json:"low"`
	Info           int `json:"info"`
	Pass           int `json:"pass"`
	ServersScanned int `json:"servers_scanned"`
}

type jsonEntry struct {
	Severity        string                  `json:"severity"`
	Server          string                  `json:"server"`
	Type            string                  `json:"type"`
	Finding         string                  `json:"finding"`
	Detail          string                  `json:"detail,omitempty"`
	ConfigPath      string                  `json:"config_path,omitempty"`
	Remediation     string                  `json:"remediation,omitempty"`
	Scope           string                  `json:"scope,omitempty"`
	Score           float64                 `json:"score,omitempty"`
	RiskScore       float64                 `json:"risk_score,omitempty"`
	RelatedFindings []scanner.FindingRef    `json:"related_findings,omitempty"`
	Compliance      []scanner.ComplianceTag `json:"compliance,omitempty"`
}

type jsonScore struct {
	Server    string              `json:"server"`
	Score     float64             `json:"score"`
	RiskScore float64             `json:"risk_score,omitempty"`
	Factors   scanner.RiskFactors `json:"riskFactors"`
}

func writeJSON(w io.Writer, results []scanner.Result, chains []scanner.Chain) error {
	counts := countBySeverity(results)
	servers := uniqueServers(results)

	entries := make([]jsonEntry, len(results))
	for i, r := range results {
		entries[i] = jsonEntry{
			Severity:        r.Severity.String(),
			Server:          r.Server,
			Type:            r.Type,
			Finding:         r.Finding,
			Detail:          r.Detail,
			ConfigPath:      r.ConfigPath,
			Remediation:     r.Remediation,
			Scope:           r.Scope,
			Score:           r.Score,
			RiskScore:       r.RiskScore,
			RelatedFindings: r.RelatedFindings,
			Compliance:      r.Compliance,
		}
	}

	type serverInfo struct {
		score     float64
		riskScore float64
		factors   scanner.RiskFactors
	}
	serverMap := map[string]serverInfo{}
	for _, r := range results {
		info := serverMap[r.Server]
		if r.Score > 0 {
			info.score = r.Score
		}
		if r.RiskScore != 0 {
			info.riskScore = r.RiskScore
		}
		if r.Score > 0 || r.Factors.TyposquatDistance > 0 {
			info.factors = r.Factors
		}
		serverMap[r.Server] = info
	}
	scores := make([]jsonScore, 0, len(servers))
	for _, srv := range servers {
		if info, ok := serverMap[srv]; ok {
			scores = append(scores, jsonScore{
				Server: srv, Score: info.score,
				RiskScore: info.riskScore, Factors: info.factors,
			})
		}
	}

	out := buildJSONOutput(counts, servers, entries, scores, chains, results)

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func buildJSONOutput(counts map[scanner.Severity]int, servers []string, entries []jsonEntry,
	scores []jsonScore, chains []scanner.Chain, results []scanner.Result) jsonOutput {
	jsonChains := make([]jsonChain, len(chains))
	for i, c := range chains {
		jsonChains[i] = jsonChain{
			Hops:        c.Hops,
			MaxSeverity: c.MaxSeverity.String(),
			Truncated:   c.Truncated,
		}
	}
	compSummary := map[string]map[string]int{}
	for _, r := range results {
		for _, tag := range r.Compliance {
			if compSummary[tag.Framework] == nil {
				compSummary[tag.Framework] = map[string]int{}
			}
			compSummary[tag.Framework][tag.Control]++
		}
	}
	return jsonOutput{
		Tool:     "mcp-audit",
		Version:  "0.1.0",
		ScanTime: time.Now().UTC().Format(time.RFC3339),
		Summary: jsonSummary{
			Critical:       counts[scanner.SevCritical],
			High:           counts[scanner.SevHigh],
			Medium:         counts[scanner.SevMedium],
			Low:            counts[scanner.SevLow],
			Info:           counts[scanner.SevInfo],
			Pass:           counts[scanner.SevPass],
			ServersScanned: len(servers),
		},
		Findings:          entries,
		Scores:            scores,
		BlastRadiusChains: jsonChains,
		ComplianceSummary: compSummary,
	}
}
