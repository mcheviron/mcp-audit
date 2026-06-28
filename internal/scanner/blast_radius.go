package scanner

import (
	"fmt"
	"strings"

	"github.com/hashicorp/go-set"
)

type ChainHop struct {
	Type     NodeType `json:"type"`
	ID       string   `json:"id"`
	Label    string   `json:"label"`
	Severity Severity `json:"severity"`
}

type Chain struct {
	Hops        []ChainHop `json:"hops"`
	MaxSeverity Severity   `json:"max_severity"`
	Truncated   bool       `json:"truncated"`
}

type NodeType string

const (
	NodeTypeCVE          NodeType = "cve"
	NodeTypeServer       NodeType = "server"
	NodeTypeConfig       NodeType = "config"
	NodeTypeCredential   NodeType = "credential"
	NodeTypeDynamic      NodeType = "dynamic"
	NodeTypeToolAnalysis NodeType = "tool_analysis"
	NodeTypeAnalysis     NodeType = "analysis"
)

type blastRadiusNode struct {
	server   string
	pkg      string
	typ      NodeType
	id       string
	label    string
	severity Severity
	config   string
}

type bfsQueueItem struct {
	node blastRadiusNode
	d    int
}

func MakeResultIDForExport(r Result) string {
	return makeResultID(r)
}

func LinkFindings(results []Result) {
	serverFindings := make(map[string][]*Result)

	for i := range results {
		serverFindings[results[i].Server] = append(serverFindings[results[i].Server], &results[i])
	}

	for i := range results {
		if results[i].Type != FindingTypeCVE {
			continue
		}
		server := results[i].Server
		for _, other := range serverFindings[server] {
			if other.Type == FindingTypeCVE {
				continue
			}
			otherID := makeResultID(*other)
			label := other.Finding
			if len(label) > 60 {
				label = label[:60]
			}
			results[i].RelatedFindings = append(results[i].RelatedFindings, FindingRef{
				ID:    otherID,
				Type:  other.Type,
				Label: label,
			})
		}
	}
}

func ComputeChains(results []Result, depth int) []Chain {
	if depth < 1 {
		depth = 3
	}
	if depth > 5 {
		depth = 5
	}

	cveNodes, credNodes, toolNodes, pkgToServers, srvToConfig := buildBlastNodes(results)

	var chains []Chain

	for _, cve := range cveNodes {
		visited := set.New[string](0)

		var hops []blastRadiusNode

		queue := []bfsQueueItem{{node: cve, d: 0}}
		visited.Insert(cve.id)

		for len(queue) > 0 {
			curr := queue[0]
			queue = queue[1:]

			hops = append(hops, curr.node)
			if curr.d >= depth {
				continue
			}

			expandBlastNode(curr.node, pkgToServers, srvToConfig, credNodes, toolNodes, visited, curr.d+1, &queue)
		}

		truncated := false
		if len(hops) > depth+1 {
			hops = hops[:depth+1]
			truncated = true
		}

		chainHops := make([]ChainHop, len(hops))
		maxSev := SevPass
		for i, h := range hops {
			chainHops[i] = ChainHop{
				Type:     h.typ,
				ID:       h.id,
				Label:    h.label,
				Severity: h.severity,
			}
			if h.severity > maxSev {
				maxSev = h.severity
			}
		}
		chains = append(chains, Chain{
			Hops:        chainHops,
			MaxSeverity: maxSev,
			Truncated:   truncated,
		})
	}

	return chains
}

func FilterByFramework(findings []Result, framework string) []Result {
	if framework == "" || framework == "all" {
		return findings
	}
	frameworks := strings.Split(framework, ",")
	for i := range frameworks {
		frameworks[i] = strings.TrimSpace(frameworks[i])
	}

	if mappings == nil {
		LoadMappings()
	}
	fullNames := set.New[string](0)
	for _, fw := range frameworks {
		if fm, ok := mappings[fw]; ok {
			fullNames.Insert(strings.ToLower(fm.Framework))
		}
		fullNames.Insert(strings.ToLower(fw))
	}

	var filtered []Result
	for _, r := range findings {
		for _, tag := range r.Compliance {
			if fullNames.Contains(strings.ToLower(tag.Framework)) {
				filtered = append(filtered, r)
				break
			}
		}
	}
	return filtered
}

func makeResultID(r Result) string {
	if r.Finding != "" {
		return fmt.Sprintf("%s-%s-%s", r.Server, r.Type, sanitizeForID(r.Finding))
	}
	return fmt.Sprintf("%s-%s-unknown", r.Server, r.Type)
}

func sanitizeForID(s string) string {
	s = strings.ToLower(s)
	s = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		return '-'
	}, s)
	if len(s) > 40 {
		s = s[:40]
	}
	return strings.Trim(s, "-")
}

func expandBlastNode(curr blastRadiusNode, pkgToServers map[string][]string, srvToConfig map[string]string,
	credNodes, toolNodes []blastRadiusNode, visited *set.Set[string], nextD int, queue *[]bfsQueueItem) {
	switch curr.typ {
	case NodeTypeCVE:
		if curr.pkg != "" {
			for _, server := range pkgToServers[curr.pkg] {
				if visited.Contains(server + "-server-hop") {
					continue
				}
				visited.Insert(server + "-server-hop")
				*queue = append(*queue, bfsQueueItem{
					node: blastRadiusNode{
						server: server,
						typ:    NodeTypeServer,
						id:     server,
						label:  fmt.Sprintf("MCP server %s (package %s)", server, curr.pkg),
					},
					d: nextD,
				})
			}
		}
	case NodeTypeServer:
		cfg := srvToConfig[curr.server]
		if cfg != "" && !visited.Contains(cfg) {
			visited.Insert(cfg)
			*queue = append(*queue, bfsQueueItem{
				node: blastRadiusNode{
					server: curr.server,
					typ:    NodeTypeConfig,
					id:     cfg,
					label:  fmt.Sprintf("config %s", cfg),
				},
				d: nextD,
			})
		}
		for _, t := range toolNodes {
			if t.server == curr.server && !visited.Contains(t.id) {
				visited.Insert(t.id)
				*queue = append(*queue, bfsQueueItem{node: t, d: nextD})
			}
		}
	case "tool_analysis", "analysis":
		for _, c := range credNodes {
			if c.server == curr.server && !visited.Contains(c.id) {
				visited.Insert(c.id)
				*queue = append(*queue, bfsQueueItem{node: c, d: nextD})
			}
		}
	}
}

func buildBlastNodes(results []Result) ([]blastRadiusNode, []blastRadiusNode, []blastRadiusNode,
	map[string][]string, map[string]string) {
	serverToPackage := make(map[string]string)
	serverToConfig := make(map[string]string)
	var cveNodes []blastRadiusNode
	var credNodes []blastRadiusNode
	var toolNodes []blastRadiusNode

	for _, r := range results {
		n := blastRadiusNode{
			server:   r.Server,
			typ:      NodeType(r.Type),
			id:       makeResultID(r),
			label:    r.Finding,
			severity: r.Severity,
			config:   r.ConfigPath,
		}
		switch r.Type {
		case FindingTypeCVE:
			n.typ = NodeTypeCVE
			pkg := r.Package
			if pkg == "" {
				pkg = extractPackageFromFinding(r.Finding)
			}
			n.pkg = pkg
			if pkg != "" {
				serverToPackage[r.Server] = pkg
			}
			cveNodes = append(cveNodes, n)
		case FindingTypeDynamic, FindingTypeCredential:
			credNodes = append(credNodes, n)
		case FindingTypeToolAnalysis, FindingTypeAnalysis:
			toolNodes = append(toolNodes, n)
		}
		serverToConfig[r.Server] = r.ConfigPath
	}
	pkgToServers := make(map[string][]string)
	for server, pkg := range serverToPackage {
		pkgToServers[pkg] = append(pkgToServers[pkg], server)
	}
	return cveNodes, credNodes, toolNodes, pkgToServers, serverToConfig
}

func extractPackageFromFinding(finding string) string {
	idx := strings.Index(finding, ": ")
	if idx >= 0 {
		finding = finding[idx+2:]
	}
	parts := strings.FieldsSeq(finding)
	for part := range parts {
		part = strings.TrimSuffix(part, ",")
		part = strings.TrimSuffix(part, ".")
		if strings.Contains(part, "/") || strings.HasPrefix(part, "@") {
			return part
		}
	}
	return ""
}
