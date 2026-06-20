package scanner

import (
	"github.com/mostafaelataby-cheviron/mcp-audit/internal/analysis"
	"github.com/mostafaelataby-cheviron/mcp-audit/internal/mcp"
)

func runCrossServerAnalysis(allTools map[string][]mcp.Tool) []Result {
	findings := analysis.Run(allTools)
	results := make([]Result, len(findings))
	for i, f := range findings {
		results[i] = Result{
			Severity: ParseSeverity(f.Severity),
			Server:   f.Server,
			Type:     f.Type,
			Finding:  f.Description,
		}
	}
	return results
}
