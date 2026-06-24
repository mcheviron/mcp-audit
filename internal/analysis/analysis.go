package analysis

import (
	"github.com/mcheviron/mcp-audit/internal/mcp"
)

type Finding struct {
	Severity    string
	Server      string
	Type        string
	Description string
}

func Run(allTools map[string][]mcp.Tool) []Finding {
	if len(allTools) < 2 {
		return nil
	}

	g := buildGraph(allTools)

	var results []Finding
	results = append(results, detectCompositionChains(g)...)
	results = append(results, detectConfusedDeputy(allTools)...)
	results = append(results, computeAdjacencyScores(g)...)

	return results
}
