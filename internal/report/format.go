package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/mostafaelataby-cheviron/mcp-audit/internal/scanner"
)

type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatSARIF Format = "sarif"
	FormatJUNIT Format = "junit"
)

func ResolveFormat(f string) Format {
	switch f {
	case "json":
		return FormatJSON
	case "sarif":
		return FormatSARIF
	case "junit":
		return FormatJUNIT
	default:
		return FormatTable
	}
}

func Write(w io.Writer, results []scanner.Result, format Format) error {
	switch format {
	case FormatJSON:
		return writeJSON(w, results)
	case FormatSARIF:
		return writeSARIF(w, results)
	case FormatJUNIT:
		return writeJUNIT(w, results)
	default:
		return writeTable(w, results)
	}
}

func writeTable(w io.Writer, results []scanner.Result) error {
	counts := countBySeverity(results)

	_, _ = fmt.Fprintf(w, "Summary: %d CRITICAL  %d HIGH  %d MEDIUM  %d LOW  %d INFO  %d PASS\n\n",
		counts[scanner.SevCritical],
		counts[scanner.SevHigh],
		counts[scanner.SevMedium],
		counts[scanner.SevLow],
		counts[scanner.SevInfo],
		counts[scanner.SevPass],
	)

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
		_, _ = fmt.Fprintf(w, "── %s ──\n", sev)

		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for _, r := range g {
			server := r.Server
			if r.ConfigPath != "" {
				server += " (" + r.ConfigPath + ")"
			}
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", colorize(r.Severity.String()), server, r.Finding)
			if r.Detail != "" {
				_, _ = fmt.Fprintf(tw, "\t\t%s\n", r.Detail)
			}
			if r.Remediation != "" {
				_, _ = fmt.Fprintf(tw, "\t\tRemediation: %s\n", r.Remediation)
			}
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		if i < len(order)-1 {
			if next, ok := groups[order[i+1]]; ok && len(next) > 0 {
				_, _ = fmt.Fprintln(w, "")
			}
		}
	}
	return nil
}

type jsonOutput struct {
	Tool     string      `json:"tool"`
	Version  string      `json:"version"`
	ScanTime string      `json:"scan_time"`
	Summary  jsonSummary `json:"summary"`
	Findings []jsonEntry `json:"findings"`
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
	Severity    string `json:"severity"`
	Server      string `json:"server"`
	Type        string `json:"type"`
	Finding     string `json:"finding"`
	Detail      string `json:"detail,omitempty"`
	ConfigPath  string `json:"config_path,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

func writeJSON(w io.Writer, results []scanner.Result) error {
	counts := countBySeverity(results)
	servers := uniqueServers(results)

	entries := make([]jsonEntry, len(results))
	for i, r := range results {
		entries[i] = jsonEntry{
			Severity:    r.Severity.String(),
			Server:      r.Server,
			Type:        r.Type,
			Finding:     r.Finding,
			Detail:      r.Detail,
			ConfigPath:  r.ConfigPath,
			Remediation: r.Remediation,
		}
	}

	out := jsonOutput{
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
		Findings: entries,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func ExitCode(results []scanner.Result) int {
	hasCritical := false
	hasHigh := false
	hasMedium := false
	for _, r := range results {
		switch r.Severity {
		case scanner.SevCritical:
			hasCritical = true
		case scanner.SevHigh:
			hasHigh = true
		case scanner.SevMedium:
			hasMedium = true
		}
	}
	if hasCritical {
		return 1
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
		sort.Slice(groups[sev], func(i, j int) bool {
			return groups[sev][i].Server < groups[sev][j].Server
		})
	}
	return groups
}

func uniqueServers(results []scanner.Result) []string {
	seen := map[string]bool{}
	var servers []string
	for _, r := range results {
		if !seen[r.Server] {
			seen[r.Server] = true
			servers = append(servers, r.Server)
		}
	}
	sort.Strings(servers)
	return servers
}
