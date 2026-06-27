package analysis

import (
	"fmt"
	"strings"

	"github.com/hashicorp/go-set"
)

type rawChain struct {
	indexes []int
	servers []string
}

func detectCompositionChains(g *toolGraph) []Finding {
	var raw []rawChain
	for i := range g.nodes {
		if !g.nodes[i].dataAccess {
			continue
		}
		paths := findPaths(g, i, 0, nil)
		for _, chain := range paths {
			if len(chain) < 2 {
				continue
			}
			last := chain[len(chain)-1]
			if !g.nodes[last].netAccess {
				continue
			}
			servers := uniqueServers(g, chain)
			if len(servers) < 2 {
				continue
			}
			raw = append(raw, rawChain{indexes: chain, servers: servers})
		}
	}
	return emitGroupedChains(g, raw)
}

func emitGroupedChains(g *toolGraph, raw []rawChain) []Finding {
	type group struct {
		examples []rawChain
		maxHops  int
		count    int
	}
	groups := map[string]*group{}
	for _, rc := range raw {
		key := strings.Join(rc.servers, " -> ")
		hops := len(rc.indexes)
		grp, ok := groups[key]
		if !ok {
			grp = &group{maxHops: hops}
			groups[key] = grp
		}
		grp.count++
		if hops > grp.maxHops {
			grp.maxHops = hops
		}
		if len(grp.examples) < 3 {
			grp.examples = append(grp.examples, rc)
		}
	}
	var results []Finding
	for seq, grp := range groups {
		maxHops := grp.maxHops
		sev := "INFO"
		desc := fmt.Sprintf("theoretical cross-server chain (%d hops, %d paths): %s", maxHops, grp.count, seq)
		if grp.count > len(grp.examples) {
			desc = fmt.Sprintf(
				"theoretical cross-server chain (%d hops): %s (%d tool-level paths found)",
				maxHops, seq, grp.count,
			)
		}
		if maxHops >= 5 {
			sev = "MEDIUM"
		}
		first := grp.examples[0]
		var detail string
		for j, ex := range grp.examples {
			if j > 0 {
				detail += "; "
			}
			detail += formatChainPath(g, ex.indexes)
		}
		if grp.count > len(grp.examples) {
			detail = fmt.Sprintf("%s; ... (%d total)", detail, grp.count)
		}
		results = append(results, Finding{
			Severity:    sev,
			Server:      first.servers[0],
			Type:        "cross-server",
			Description: desc,
			Detail:      detail,
		})
	}
	return results
}

func uniqueServers(g *toolGraph, chain []int) []string {
	seen := set.New[string](0)
	var out []string
	for _, idx := range chain {
		srv := g.nodes[idx].server
		if srv != "" && !seen.Contains(srv) {
			seen.Insert(srv)
			out = append(out, srv)
		}
	}
	return out
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
