package report

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/hashicorp/go-set"
	"github.com/mostafaelataby-cheviron/mcp-audit/internal/scanner"
)

type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatSARIF Format = "sarif"
	FormatJUnit Format = "junit"
)

type CIInfo struct {
	Repo      string
	Branch    string
	CommitSHA string
	Enabled   bool
}

func ResolveFormat(f string) Format {
	switch f {
	case "json":
		return FormatJSON
	case "sarif":
		return FormatSARIF
	case "junit":
		return FormatJUnit
	default:
		return FormatTable
	}
}

func Write(w io.Writer, results []scanner.Result, chains []scanner.Chain, format Format, ci *CIInfo) error {
	switch format {
	case FormatJSON:
		return writeJSON(w, results, chains)
	case FormatSARIF:
		return writeSARIF(w, results, ci)
	case FormatJUnit:
		return writeJUnit(w, results)
	default:
		return writeTable(w, results, chains)
	}
}

func writeSummaryLine(w io.Writer, counts map[scanner.Severity]int) error {
	_, err := fmt.Fprintf(w, "Summary: %d CRITICAL  %d HIGH  %d MEDIUM  %d LOW  %d INFO  %d PASS\n\n",
		counts[scanner.SevCritical], counts[scanner.SevHigh], counts[scanner.SevMedium],
		counts[scanner.SevLow], counts[scanner.SevInfo], counts[scanner.SevPass])
	return err
}

func writeComplianceSummary(w io.Writer, results []scanner.Result) {
	summary := map[string]map[string]int{}
	for _, r := range results {
		for _, tag := range r.Compliance {
			if summary[tag.Framework] == nil {
				summary[tag.Framework] = map[string]int{}
			}
			summary[tag.Framework][tag.Control]++
		}
	}
	if len(summary) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w, "── Compliance Summary ──")
	frameworks := slices.Sorted(maps.Keys(summary))
	for _, fw := range frameworks {
		controls := summary[fw]
		ctrlIDs := slices.Sorted(maps.Keys(controls))
		for _, c := range ctrlIDs {
			_, _ = fmt.Fprintf(w, "  %s / %s: %d findings\n", fw, c, controls[c])
		}
	}
	_, _ = fmt.Fprintln(w, "")
}

func writeBlastChains(w io.Writer, chains []scanner.Chain) {
	if len(chains) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w, "── Blast-Radius Chains ──")
	for _, chain := range chains {
		for j, hop := range chain.Hops {
			indent := strings.Repeat("  ", j)
			_, _ = fmt.Fprintf(w, "  %s%s %s: %s\n", indent, hop.Type, hop.ID, hop.Label)
		}
		if chain.Truncated {
			_, _ = fmt.Fprintln(w, "    (truncated)")
		}
	}
	_, _ = fmt.Fprintln(w, "")
}

func WriteCISummary(w io.Writer, results []scanner.Result, serversScanned int) error {
	counts := countBySeverity(results)
	s := jsonSummary{
		Critical:       counts[scanner.SevCritical],
		High:           counts[scanner.SevHigh],
		Medium:         counts[scanner.SevMedium],
		Low:            counts[scanner.SevLow],
		Info:           counts[scanner.SevInfo],
		Pass:           counts[scanner.SevPass],
		ServersScanned: serversScanned,
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}

func writeTable(w io.Writer, results []scanner.Result, chains []scanner.Chain) error {
	counts := countBySeverity(results)
	if err := writeSummaryLine(w, counts); err != nil {
		return err
	}
	if err := writeScoreSection(w, results); err != nil {
		return err
	}
	if err := writeTrustScoreSection(w, results); err != nil {
		return err
	}
	writeComplianceSummary(w, results)
	writeBlastChains(w, chains)
	groups := groupBySeverity(results)
	order := []scanner.Severity{
		scanner.SevCritical, scanner.SevHigh, scanner.SevMedium,
		scanner.SevLow, scanner.SevInfo, scanner.SevPass,
	}

	for i, sev := range order {
		g, ok := groups[sev]
		if !ok || len(g) == 0 {
			continue
		}
		if _, err := fmt.Fprintf(w, "── %s ──\n", sev); err != nil {
			return err
		}

		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for _, r := range g {
			server := r.Server
			if r.ConfigPath != "" {
				label := r.ConfigPath
				if r.Scope == "project" {
					label += " (project)"
				}
				server += " (" + label + ")"
			}
			if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\n", colorize(r.Severity.String()), server, r.Finding); err != nil {
				return err
			}
			if r.Detail != "" {
				if _, err := fmt.Fprintf(tw, "\t\t%s\n", r.Detail); err != nil {
					return err
				}
			}
			if r.Remediation != "" {
				if _, err := fmt.Fprintf(tw, "\t\tRemediation: %s\n", r.Remediation); err != nil {
					return err
				}
			}
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		if i < len(order)-1 {
			if next, ok := groups[order[i+1]]; ok && len(next) > 0 {
				if _, err := fmt.Fprintln(w, ""); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

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
	TrustScore      float64                 `json:"trust_score,omitempty"`
	RelatedFindings []scanner.FindingRef    `json:"related_findings,omitempty"`
	Compliance      []scanner.ComplianceTag `json:"compliance,omitempty"`
}

type jsonScore struct {
	Server     string              `json:"server"`
	Score      float64             `json:"score"`
	TrustScore float64             `json:"trust_score,omitempty"`
	Factors    scanner.RiskFactors `json:"riskFactors"`
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
			TrustScore:      r.TrustScore,
			RelatedFindings: r.RelatedFindings,
			Compliance:      r.Compliance,
		}
	}

	type serverInfo struct {
		score      float64
		trustScore float64
		factors    scanner.RiskFactors
	}
	serverMap := map[string]serverInfo{}
	for _, r := range results {
		info := serverMap[r.Server]
		if r.Score > 0 {
			info.score = r.Score
		}
		if r.TrustScore != 0 {
			info.trustScore = r.TrustScore
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
				TrustScore: info.trustScore, Factors: info.factors,
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

func ExitCode(results []scanner.Result) int {
	hasHigh := false
	hasMedium := false
	for _, r := range results {
		switch r.Severity {
		case scanner.SevCritical:
			return 1
		case scanner.SevHigh:
			hasHigh = true
		case scanner.SevMedium:
			hasMedium = true
		}
	}
	if hasHigh {
		return 2
	}
	if hasMedium {
		return 3
	}
	return 0
}

func PrintSummary(results []scanner.Result, serversScanned int) {
	counts := countBySeverity(results)

	fmt.Fprintf(os.Stderr,
		"%d CRITICAL  %d HIGH  %d MEDIUM  %d LOW  %d INFO  %d PASS  —  %d servers scanned\n",
		counts[scanner.SevCritical],
		counts[scanner.SevHigh],
		counts[scanner.SevMedium],
		counts[scanner.SevLow],
		counts[scanner.SevInfo],
		counts[scanner.SevPass],
		serversScanned,
	)
}

func countBySeverity(results []scanner.Result) map[scanner.Severity]int {
	counts := map[scanner.Severity]int{}
	for _, r := range results {
		counts[r.Severity]++
	}
	return counts
}

func groupBySeverity(results []scanner.Result) map[scanner.Severity][]scanner.Result {
	groups := map[scanner.Severity][]scanner.Result{}
	for _, r := range results {
		groups[r.Severity] = append(groups[r.Severity], r)
	}
	for sev := range groups {
		slices.SortFunc(groups[sev], func(a, b scanner.Result) int {
			return cmp.Compare(a.Server, b.Server)
		})
	}
	return groups
}

func writeTrustScoreSection(w io.Writer, results []scanner.Result) error {
	scores := collectScores(results, func(r scanner.Result) (float64, bool) {
		if r.TrustScore == 0 {
			return 0, false
		}
		if r.TrustScore == -1 {
			return -1, true
		}
		return r.TrustScore, true
	})
	return writeScoreTable(w, "── Adversarial Trust Scores ──", scores, func(score float64) string {
		if score == -1 {
			return "untestable"
		}
		return fmt.Sprintf("%.0f/100", score)
	})
}

func writeScoreSection(w io.Writer, results []scanner.Result) error {
	scores := collectScores(results, func(r scanner.Result) (float64, bool) {
		return r.Score, r.Score > 0
	})
	return writeScoreTable(w, "── Security Scores ──", scores, func(score float64) string {
		return fmt.Sprintf("%.0f/100", score)
	})
}

func collectScores(results []scanner.Result, pick func(scanner.Result) (float64, bool)) map[string]float64 {
	scores := map[string]float64{}
	for _, r := range results {
		if v, ok := pick(r); ok {
			scores[r.Server] = v
		}
	}
	return scores
}

func writeScoreTable(w io.Writer, header string, scores map[string]float64, format func(float64) string) error {
	if len(scores) == 0 {
		return nil
	}
	if _, err := fmt.Fprintln(w, header); err != nil {
		return err
	}
	servers := slices.Sorted(maps.Keys(scores))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, server := range servers {
		if _, err := fmt.Fprintf(tw, "%s\t%s\n", server, format(scores[server])); err != nil {
			return err
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintln(w, "")
	return err
}

func uniqueServers(results []scanner.Result) []string {
	seen := set.New[string](0)
	var servers []string
	for _, r := range results {
		if !seen.Contains(r.Server) {
			seen.Insert(r.Server)
			servers = append(servers, r.Server)
		}
	}
	sort.Strings(servers)
	return servers
}

func UniqueServerCount(results []scanner.Result) int {
	return len(uniqueServers(results))
}
