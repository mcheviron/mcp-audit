package scanner

import (
	"fmt"

	"github.com/mostafaelataby-cheviron/mcp-audit/internal/mcp"
)

func detectToolShadowing(allTools map[string][]mcp.Tool) []Result {
	type toolRef struct {
		server      string
		description string
	}
	seen := make(map[string][]toolRef)

	for srv, tools := range allTools {
		for _, t := range tools {
			seen[t.Name] = append(seen[t.Name], toolRef{srv, t.Description})
		}
	}

	var results []Result
	for name, refs := range seen {
		if len(refs) < 2 {
			continue
		}
		for i := range refs {
			for j := i + 1; j < len(refs); j++ {
				if refs[i].description != refs[j].description {
					results = append(results, Result{
						Severity: SevMedium,
						Server:   refs[i].server,
						Type:     "static",
						Finding: fmt.Sprintf(
							"tool %q shadowing: %q and %q have conflicting descriptions",
							name, refs[i].server, refs[j].server),
					})
				} else {
					results = append(results, Result{
						Severity: SevInfo,
						Server:   refs[i].server,
						Type:     "static",
						Finding: fmt.Sprintf(
							"tool %q exposed by %q and %q with identical descriptions — potential impersonation",
							name, refs[i].server, refs[j].server),
					})
				}
			}
		}
	}

	return results
}
