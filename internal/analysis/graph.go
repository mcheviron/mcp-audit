package analysis

import (
	"slices"
	"strings"

	"github.com/mostafaelataby-cheviron/mcp-audit/internal/mcp"
)

type toolNode struct {
	server     string
	toolName   string
	inputTypes []string
	outputType string
	dataAccess bool
	netAccess  bool
}

type toolGraph struct {
	nodes []toolNode
	edges map[int][]int
}

func buildGraph(allTools map[string][]mcp.Tool) *toolGraph {
	var nodes []toolNode
	for server, tools := range allTools {
		for _, t := range tools {
			n := toolNode{
				server:     server,
				toolName:   t.Name,
				outputType: classifyOutput(t),
			}
			n.inputTypes = classifyInputs(t.InputSchema)
			n.dataAccess = hasCapability(n.inputTypes, "filesystem", "database", "environment")
			n.netAccess = hasCapability(n.inputTypes, "url", "network")
			if n.outputType == "url" || n.outputType == "network" {
				n.netAccess = true
			}
			nodes = append(nodes, n)
		}
	}

	edges := make(map[int][]int)
	for i := range nodes {
		for j := range nodes {
			if i == j {
				continue
			}
			if nodes[i].server == nodes[j].server {
				continue
			}
			if connects(nodes[i], nodes[j]) {
				edges[i] = append(edges[i], j)
			}
		}
	}

	return &toolGraph{nodes: nodes, edges: edges}
}

func connects(from, to toolNode) bool {
	fromType := from.outputType
	if fromType == "" {
		return false
	}
	if fromType == "text" || fromType == "json" {
		return true
	}
	if len(to.inputTypes) > 0 {
		return true
	}
	return slices.Contains(to.inputTypes, fromType)
}

func hasCapability(types []string, targets ...string) bool {
	for _, t := range types {
		if slices.Contains(targets, t) {
			return true
		}
	}
	return false
}

func classifyInputs(schema map[string]any) []string {
	props, _ := schema["properties"].(map[string]any)
	if props == nil {
		return nil
	}
	seen := map[string]bool{}
	var types []string
	for key, val := range props {
		propMap, ok := val.(map[string]any)
		if !ok {
			continue
		}
		desc, _ := propMap["description"].(string)
		t := classifyType(key, desc)
		if !seen[t] {
			seen[t] = true
			types = append(types, t)
		}
	}
	return types
}

func classifyOutput(tool mcp.Tool) string {
	desc := strings.ToLower(tool.Description)
	switch {
	case strings.Contains(desc, "return") && (strings.Contains(desc, "url") || strings.Contains(desc, "uri")):
		return "url"
	case strings.Contains(desc, "return") && strings.Contains(desc, "file"):
		return "filesystem"
	case strings.Contains(desc, "json") || strings.Contains(desc, "list"):
		return "json"
	default:
		return "text"
	}
}

func classifyType(name, desc string) string {
	combined := strings.ToLower(name) + " " + strings.ToLower(desc)

	if matchAny(combined, "url", "uri", "endpoint", "href") {
		return "url"
	}
	if matchAny(combined, "file", "path", "directory", "folder", "filename") {
		return "filesystem"
	}
	if strings.Contains(combined, "json") {
		return "json"
	}
	if matchAny(combined, "command", "cmd", "shell", "script", "exec") {
		return "command"
	}
	if matchAny(combined, "binary", "image", "blob") {
		return "binary"
	}
	if matchAny(combined, "database", "sql", "query", "collection", "table") {
		return "database"
	}
	if matchAny(combined, "env", "environment", "variable") {
		return "environment"
	}
	return "text"
}

func matchAny(s string, terms ...string) bool {
	for _, t := range terms {
		if strings.Contains(s, t) {
			return true
		}
	}
	return false
}
