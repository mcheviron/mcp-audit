package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/mostafaelataby-cheviron/mcp-audit/internal/scanner"
)

type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatSARIF Format = "sarif"
)

func ResolveFormat(f string) Format {
	switch f {
	case "json":
		return FormatJSON
	case "sarif":
		return FormatSARIF
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
	default:
		return writeTable(w, results)
	}
}

func writeTable(w io.Writer, results []scanner.Result) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, r := range results {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", colorize(r.Severity.String()), r.Server, r.Finding)
		if r.Detail != "" {
			_, _ = fmt.Fprintf(tw, "\t\t%s\n", r.Detail)
		}
	}
	return tw.Flush()
}

func writeJSON(w io.Writer, results []scanner.Result) error {
	type entry struct {
		Severity string `json:"severity"`
		Server   string `json:"server"`
		Type     string `json:"type"`
		Finding  string `json:"finding"`
		Detail   string `json:"detail,omitempty"`
	}

	entries := make([]entry, len(results))
	for i, r := range results {
		entries[i] = entry{
			Severity: r.Severity.String(),
			Server:   r.Server,
			Type:     r.Type,
			Finding:  r.Finding,
			Detail:   r.Detail,
		}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(entries)
}

func ExitCode(results []scanner.Result) int {
	for _, r := range results {
		if r.Severity == scanner.SevCritical || r.Severity == scanner.SevHigh {
			return 1
		}
	}
	return 0
}

func PrintSummary(results []scanner.Result, serversScanned int) {
	counts := map[scanner.Severity]int{}
	for _, r := range results {
		counts[r.Severity]++
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
