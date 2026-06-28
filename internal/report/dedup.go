package report

import (
	"strings"

	"github.com/mcheviron/mcp-audit/internal/scanner"
)

func Deduplicate(results []scanner.Result) []scanner.Result {
	type key struct {
		server  string
		typ     scanner.FindingType
		finding string
	}
	seen := map[key]int{}
	var deduped []scanner.Result
	for _, r := range results {
		norm := normalizeFinding(r.Finding)
		k := key{r.Server, r.Type, norm}
		if idx, ok := seen[k]; ok {
			if r.Severity > deduped[idx].Severity {
				deduped[idx].Severity = r.Severity
			}
			if r.Detail != "" && !strings.Contains(deduped[idx].Detail, r.Detail) {
				if deduped[idx].Detail != "" {
					deduped[idx].Detail += "; " + r.Detail
				} else {
					deduped[idx].Detail = r.Detail
				}
			}
			if r.Remediation != "" && deduped[idx].Remediation == "" {
				deduped[idx].Remediation = r.Remediation
			}
			continue
		}
		seen[k] = len(deduped)
		deduped = append(deduped, r)
	}
	return deduped
}

func normalizeFinding(s string) string {
	s = strings.ToLower(s)
	fields := strings.Fields(s)
	return strings.Join(fields, " ")
}
