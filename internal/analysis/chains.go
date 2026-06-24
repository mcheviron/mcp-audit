package analysis

import (
	"fmt"
	"strings"

	"github.com/hashicorp/go-set"
)

func detectCompositionChains(g *toolGraph) []Finding {
	var results []Finding

	for i := range g.nodes {
		if !g.nodes[i].dataAccess {
			continue
		}
		chains := findPaths(g, i, 0, nil)
		for _, chain := range chains {
			if len(chain) < 2 {
				continue
			}
			last := chain[len(chain)-1]
			if !g.nodes[last].netAccess {
				continue
			}
			chainLen := len(chain)
			sev := "MEDIUM"
			if chainLen > 3 {
				sev = "INFO"
			}
			path := formatChainPath(g, chain)
			finding := fmt.Sprintf("potential data exfiltration chain: %s", path)
			if chainLen > 3 {
				finding = fmt.Sprintf("long composition chain (%d hops): %s", chainLen, path)
			}
			results = append(results, Finding{
				Severity:    sev,
				Server:      g.nodes[i].server,
				Type:        "cross-server",
				Description: finding,
			})
		}
	}

	return results
}

func findPaths(g *toolGraph, from int, depth int, visited *set.Set[int]) [][]int {
	if depth > 4 {
		return nil
	}
	if visited == nil {
		visited = set.New[int](0)
	}
	visited.Insert(from)
	defer visited.Remove(from)

	var chains [][]int

	if depth > 0 && g.nodes[from].netAccess && g.nodes[from].server != "" {
		chains = append(chains, nil)
	}

	for _, next := range g.edges[from] {
		if visited.Contains(next) {
			continue
		}
		chains = append(chains, findPaths(g, next, depth+1, visited)...)
	}

	for i := range chains {
		chains[i] = append([]int{from}, chains[i]...)
	}

	return chains
}

func formatChainPath(g *toolGraph, chain []int) string {
	parts := make([]string, len(chain))
	for i, idx := range chain {
		parts[i] = fmt.Sprintf("%s/%s", g.nodes[idx].server, g.nodes[idx].toolName)
	}
	return strings.Join(parts, " -> ")
}
