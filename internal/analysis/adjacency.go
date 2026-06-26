package analysis

import (
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/go-set"
	"github.com/mcheviron/mcp-audit/internal/mcp"
)

func detectConfusedDeputy(allTools map[string][]mcp.Tool) []Finding {
	var results []Finding

	for server, tools := range allTools {
		for _, tool := range tools {
			if !toolTakesURL(tool) {
				continue
			}
			if !hasForwardingKeywords(tool.Description) {
				continue
			}
			if adjacentToNetwork(tool, server, allTools) {
				results = append(results, Finding{
					Severity: "MEDIUM",
					Server:   server,
					Type:     "cross-server",
					Description: fmt.Sprintf(
						"potential confused deputy: tool %q in server %q forwards URLs to another server's network-access tool",
						tool.Name, server),
				})
			}
		}
	}

	return results
}

func toolTakesURL(tool mcp.Tool) bool {
	props, _ := tool.InputSchema["properties"].(map[string]any)
	if props == nil {
		return false
	}
	for key, val := range props {
		propMap, ok := val.(map[string]any)
		if !ok {
			continue
		}
		desc, _ := propMap["description"].(string)
		t := classifyType(key, desc)
		if t == "url" {
			return true
		}
	}
	return false
}

func hasForwardingKeywords(desc string) bool {
	return matchAny(strings.ToLower(desc), "forward", "proxy", "redirect", "pass", "relay", "delegate", "pipe")
}

func adjacentToNetwork(tool mcp.Tool, ownServer string, allTools map[string][]mcp.Tool) bool {
	for otherServer, tools := range allTools {
		if otherServer == ownServer {
			continue
		}
		if slices.ContainsFunc(tools, toolHasNetworkCapability) {
			return true
		}
	}
	return false
}

func toolHasNetworkCapability(tool mcp.Tool) bool {
	props, _ := tool.InputSchema["properties"].(map[string]any)
	if props == nil {
		return false
	}
	for key, val := range props {
		propMap, ok := val.(map[string]any)
		if !ok {
			continue
		}
		desc, _ := propMap["description"].(string)
		t := classifyType(key, desc)
		if t == "url" || t == "network" {
			return true
		}
	}
	outType := classifyOutput(tool)
	if outType == "url" || outType == "network" {
		return true
	}
	return false
}

type capSummary struct {
	filesystem bool
	shell      bool
	network    bool
	database   bool
	unknown    bool
}

func (c capSummary) score() int {
	s := 0
	if c.filesystem {
		s += 3
	}
	if c.shell {
		s += 5
	}
	if c.network {
		s += 2
	}
	if c.database {
		s += 2
	}
	if c.unknown {
		s++
	}
	return s
}

func (c capSummary) breakdown() string {
	var parts []string
	if c.filesystem {
		parts = append(parts, "filesystem=3")
	}
	if c.shell {
		parts = append(parts, "shell=5")
	}
	if c.network {
		parts = append(parts, "network=2")
	}
	if c.database {
		parts = append(parts, "database=2")
	}
	if c.unknown {
		parts = append(parts, "unknown=1")
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

func computeAdjacencyScores(g *toolGraph) []Finding {
	serverCaps := make(map[string]capSummary)
	serverNames := set.New[string](0)

	for _, n := range g.nodes {
		serverNames.Insert(n.server)
		cs := serverCaps[n.server]
		for _, t := range n.inputTypes {
			switch t {
			case "filesystem":
				cs.filesystem = true
			case "command":
				cs.shell = true
			case "url":
				cs.network = true
			case "database":
				cs.database = true
			case "text", "json", "binary":
				cs.unknown = true
			}
		}
		if n.netAccess {
			cs.network = true
		}
		if n.dataAccess {
			cs.filesystem = true
		}
		serverCaps[n.server] = cs
	}

	servers := serverNames.Slice()

	serverToNodes := make(map[string][]int, len(g.nodes))
	for i, n := range g.nodes {
		serverToNodes[n.server] = append(serverToNodes[n.server], i)
	}

	var results []Finding
	for i, srvA := range servers {
		neighborScore := 0
		var neighborCaps []string
		for j, srvB := range servers {
			if i == j {
				continue
			}
			if !serversAdjacentIndexed(g, serverToNodes, srvA, srvB) {
				continue
			}
			csB := serverCaps[srvB]
			neighborScore += csB.score()
			if bd := csB.breakdown(); bd != "none" {
				neighborCaps = append(neighborCaps, srvB+"("+bd+")")
			}
		}
		if neighborScore > 5 {
			results = append(results, Finding{
				Severity: "INFO",
				Server:   srvA,
				Type:     "cross-server",
				Description: fmt.Sprintf(
					"elevated cross-server risk: server %q adjacency score %d from neighbors: %s",
					srvA, neighborScore, strings.Join(neighborCaps, "; ")),
			})
		}
	}

	return results
}

func serversAdjacentIndexed(g *toolGraph, idx map[string][]int, a, b string) bool {
	for _, i := range idx[a] {
		for _, j := range g.edges[i] {
			if g.nodes[j].server == b {
				return true
			}
		}
	}
	return false
}
