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

	"github.com/hashicorp/go-set"
	"github.com/mcheviron/mcp-audit/internal/scanner"
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

func Write(
	w io.Writer, results []scanner.Result, chains []scanner.Chain,
	format Format, ci *CIInfo, opts TableOptions,
) error {
	switch format {
	case FormatJSON:
		return writeJSON(w, results, chains)
	case FormatSARIF:
		return writeSARIF(w, results, ci)
	case FormatJUnit:
		return writeJUnit(w, results)
	default:
		return writeTable(w, results, chains, opts)
	}
}

func writeSummaryLine(w io.Writer, counts map[scanner.Severity]int) error {
	if allZero(counts) {
		return nil
	}
	_, err := fmt.Fprintf(w, "Summary: %d CRITICAL  %d HIGH  %d MEDIUM  %d LOW  %d INFO  %d PASS\n\n",
		counts[scanner.SevCritical], counts[scanner.SevHigh], counts[scanner.SevMedium],
		counts[scanner.SevLow], counts[scanner.SevInfo], counts[scanner.SevPass])
	return err
}

func allZero(counts map[scanner.Severity]int) bool {
	for _, v := range counts {
		if v != 0 {
			return false
		}
	}
	return true
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

func writeTable(w io.Writer, results []scanner.Result, chains []scanner.Chain, opts TableOptions) error {
	counts := countBySeverity(results)
	if err := writeSummaryLine(w, counts); err != nil {
		return err
	}
	if err := writeScoreSection(w, results); err != nil {
		return err
	}
	if err := writeRiskScoreSection(w, results); err != nil {
		return err
	}
	writeComplianceSummary(w, results)
	writeBlastChains(w, chains)
	groups := groupBySeverity(results)
	order := []scanner.Severity{
		scanner.SevCritical, scanner.SevHigh, scanner.SevMedium,
		scanner.SevLow, scanner.SevInfo, scanner.SevPass,
	}

	emitted := 0
	for _, sev := range order {
		g, ok := groups[sev]
		if !ok || len(g) == 0 {
			continue
		}
		if emitted > 0 {
			if _, err := fmt.Fprintln(w, ""); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "── %s ──\n", sev); err != nil {
			return err
		}
		emitted++
		if err := writeSeverityGroup(w, g, opts); err != nil {
			return err
		}
	}
	return nil
}

func writeSeverityGroup(w io.Writer, g []scanner.Result, opts TableOptions) error {
	serverWidth := 0
	for _, r := range g {
		if l := len(r.Server); l > serverWidth {
			serverWidth = l
		}
	}
	remIndent := "↳ Remediation: "
	remPrefixLen := 2 + serverWidth + 2 + len(remIndent)
	remWidth := contentWidth(opts.Width, remPrefixLen)

	paths := make([]string, 0)
	pathIndex := map[string]int{}
	for _, r := range g {
		key := r.ConfigPath + "|" + r.Scope
		if _, ok := pathIndex[key]; !ok {
			pathIndex[key] = len(paths)
			paths = append(paths, key)
		}
	}
	sort.Strings(paths)

	for _, key := range paths {
		parts := strings.SplitN(key, "|", 2)
		path, scope := parts[0], parts[1]
		if path != "" {
			label := path
			if scope == "project" {
				label += " (project)"
			}
			if _, err := fmt.Fprintf(w, "  %s\n", label); err != nil {
				return err
			}
		}
		for _, r := range g {
			if r.ConfigPath != path || r.Scope != scope {
				continue
			}
			padded := r.Server + strings.Repeat(" ", serverWidth-len(r.Server))
			if _, err := fmt.Fprintf(w, "%s  %s  %s\n",
				colorize(r.Severity.String()), padded, r.Finding); err != nil {
				return err
			}
			if r.Detail != "" {
				indent := strings.Repeat(" ", 2+serverWidth+2)
				if err := writeWrapped(w, "", indent, r.Detail, remWidth); err != nil {
					return err
				}
			}
			if r.Remediation != "" &&
				(r.Severity != scanner.SevPass || opts.ShowPassRemediation) {
				indent := strings.Repeat(" ", 2+serverWidth+2)
				if err := writeWrapped(w, remIndent, indent, r.Remediation, remWidth); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func ExitCode(results []scanner.Result, scanErrored bool) int {
	if scanErrored {
		return 2
	}
	for _, r := range results {
		if r.Severity == scanner.SevCritical || r.Severity == scanner.SevHigh {
			return 1
		}
	}
	return 0
}

func PrintSummary(results []scanner.Result, serversScanned int) {
	counts := countBySeverity(results)
	if allZero(counts) {
		fmt.Fprintf(os.Stderr, "0 findings — %d servers scanned\n", serversScanned)
		return
	}

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

func writeRiskScoreSection(w io.Writer, results []scanner.Result) error {
	scores := collectScores(results, func(r scanner.Result) (float64, bool) {
		if r.RiskScore == 0 {
			return 0, false
		}
		if r.RiskScore == -1 {
			return -1, true
		}
		return r.RiskScore, true
	})
	return writeScoreTable(w, "── Adversarial Risk Scores ──", scores, func(score float64) string {
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
