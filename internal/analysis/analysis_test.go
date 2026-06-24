package analysis

import (
	"testing"

	"github.com/mcheviron/mcp-audit/internal/mcp"
)

func makeTool(name, desc string, props map[string]any) mcp.Tool {
	schema := map[string]any{}
	if props != nil {
		schema["properties"] = props
	}
	return mcp.Tool{Name: name, Description: desc, InputSchema: schema}
}

func TestBuildGraphSingleServer(t *testing.T) {
	allTools := map[string][]mcp.Tool{
		"server-a": {
			makeTool("read_file", "read a file from disk", map[string]any{
				"path": map[string]any{"type": "string", "description": "file path to read"},
			}),
		},
	}
	g := buildGraph(allTools)
	if len(g.nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(g.nodes))
	}
	if len(g.edges) > 0 {
		t.Errorf("expected 0 edges for single server, got %d", len(g.edges))
	}
}

func TestBuildGraphTwoServer(t *testing.T) {
	allTools := map[string][]mcp.Tool{
		"filesystem-server": {
			makeTool("read_file", "read a file from disk", map[string]any{
				"path": map[string]any{"type": "string", "description": "file path to read"},
			}),
		},
		"network-server": {
			makeTool("fetch_url", "fetch content from a URL", map[string]any{
				"url": map[string]any{"type": "string", "description": "URL to fetch"},
			}),
		},
	}
	g := buildGraph(allTools)
	if len(g.nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(g.nodes))
	}
}

func TestBuildGraphThreeServer(t *testing.T) {
	allTools := map[string][]mcp.Tool{
		"fs": {
			makeTool("read", "read a file returning text", map[string]any{
				"filename": map[string]any{"type": "string"},
			}),
		},
		"db": {
			makeTool("query", "run a database query", map[string]any{
				"sql": map[string]any{"type": "string"},
			}),
		},
		"net": {
			makeTool("fetch", "fetch a URL returning text", map[string]any{
				"url": map[string]any{"type": "string"},
			}),
		},
	}
	g := buildGraph(allTools)
	if len(g.nodes) != 3 {
		t.Fatalf("expected 3 nodes, got %d", len(g.nodes))
	}
}

func TestChainDetectionFilesystemToNetwork(t *testing.T) {
	allTools := map[string][]mcp.Tool{
		"fs-srv": {
			makeTool("read_file", "read a file and return its text content", map[string]any{
				"path": map[string]any{"type": "string", "description": "path to file"},
			}),
		},
		"net-srv": {
			makeTool("download", "download content from a URL", map[string]any{
				"url": map[string]any{"type": "string", "description": "target URL"},
			}),
		},
	}
	g := buildGraph(allTools)
	chains := detectCompositionChains(g)
	if len(chains) == 0 {
		t.Error("expected chain detection between fs-srv/read_file and net-srv/download")
	}
}

func TestChainDetectionNoChainSafe(t *testing.T) {
	allTools := map[string][]mcp.Tool{
		"echo-srv": {
			makeTool("echo", "echo back the input text", map[string]any{
				"text": map[string]any{"type": "string"},
			}),
		},
		"calc-srv": {
			makeTool("add", "add two numbers", map[string]any{
				"a": map[string]any{"type": "number"},
				"b": map[string]any{"type": "number"},
			}),
		},
	}
	g := buildGraph(allTools)
	chains := detectCompositionChains(g)
	if len(chains) > 0 {
		t.Errorf("expected no chains for safe config, got %d", len(chains))
	}
}

func TestChainDetectionNoCrossServerEdges(t *testing.T) {
	allTools := map[string][]mcp.Tool{
		"readonly-srv": {
			makeTool("read_file", "read a file returning text", map[string]any{
				"path": map[string]any{"type": "string", "description": "path to read"},
			}),
		},
		"format-srv": {
			makeTool("format_text", "format text with a template", map[string]any{
				"template": map[string]any{"type": "string"},
			}),
		},
	}
	g := buildGraph(allTools)
	chains := detectCompositionChains(g)
	if len(chains) > 0 {
		t.Errorf("expected no chains when no network tool, got %d", len(chains))
	}
	for _, c := range chains {
		t.Logf("unexpected chain: %s", c.Description)
	}
}

func TestConfusedDeputyDetected(t *testing.T) {
	allTools := map[string][]mcp.Tool{
		"proxy-srv": {
			makeTool("url_forwarder", "forwards URL requests to internal services", map[string]any{
				"url": map[string]any{"type": "string", "description": "URL to forward"},
			}),
		},
		"fetch-srv": {
			makeTool("fetch_url", "fetch an external URL", map[string]any{
				"url": map[string]any{"type": "string", "description": "URL to fetch"},
			}),
		},
	}
	findings := detectConfusedDeputy(allTools)
	found := false
	for _, f := range findings {
		if f.Server == "proxy-srv" {
			found = true
		}
	}
	if !found {
		t.Error("expected confused deputy detection for proxy-srv/url_forwarder")
	}
}

func TestConfusedDeputyNoForwardingKeywords(t *testing.T) {
	allTools := map[string][]mcp.Tool{
		"input-srv": {
			makeTool("validate_url", "validate a URL format", map[string]any{
				"url": map[string]any{"type": "string", "description": "URL to validate"},
			}),
		},
		"fetch-srv": {
			makeTool("fetch_url", "fetch an external URL", map[string]any{
				"url": map[string]any{"type": "string", "description": "URL to fetch"},
			}),
		},
	}
	findings := detectConfusedDeputy(allTools)
	if len(findings) > 0 {
		t.Errorf("expected no confused deputy for validate_url (not forwarding), got %d", len(findings))
	}
}

func TestAdjacencyScoringElevated(t *testing.T) {
	allTools := map[string][]mcp.Tool{
		"fs-srv": {
			makeTool("read_file", "read a file from path", map[string]any{
				"path": map[string]any{"type": "string"},
			}),
		},
		"net-srv": {
			makeTool("download", "download from URL", map[string]any{
				"url": map[string]any{"type": "string"},
			}),
		},
		"shell-srv": {
			makeTool("exec", "execute a command", map[string]any{
				"command": map[string]any{"type": "string"},
			}),
		},
	}
	g := buildGraph(allTools)
	scores := computeAdjacencyScores(g)
	if len(scores) == 0 {
		t.Error("expected adjacency scores for multi-server graph")
	}
	for _, s := range scores {
		if s.Severity != "INFO" {
			t.Errorf("expected INFO severity for adjacency score, got %s", s.Severity)
		}
	}
}

func TestAdjacencyScoringLow(t *testing.T) {
	allTools := map[string][]mcp.Tool{
		"echo-srv": {
			makeTool("echo", "echo text back", map[string]any{
				"text": map[string]any{"type": "string"},
			}),
		},
	}
	g := buildGraph(allTools)
	scores := computeAdjacencyScores(g)
	if len(scores) > 0 {
		t.Errorf("expected no scores for single isolated server, got %d", len(scores))
	}
}

func TestRunWithSingleServer(t *testing.T) {
	allTools := map[string][]mcp.Tool{
		"lonely-srv": {
			makeTool("read_file", "read a file returning text", map[string]any{
				"path": map[string]any{"type": "string", "description": "path to read"},
			}),
		},
	}
	findings := Run(allTools)
	if len(findings) > 0 {
		t.Errorf("expected no cross-server findings for single server, got %d", len(findings))
	}
}

func TestRunWithMultipleServers(t *testing.T) {
	allTools := map[string][]mcp.Tool{
		"filesystem-srv": {
			makeTool("read_file", "read a file and return its text content", map[string]any{
				"filename": map[string]any{"type": "string", "description": "path to file"},
			}),
		},
		"network-srv": {
			makeTool("fetch_url", "fetch content from a URL endpoint", map[string]any{
				"url": map[string]any{"type": "string", "description": "target URL"},
			}),
		},
		"proxy-srv": {
			makeTool("forward", "forward requests to another server", map[string]any{
				"url": map[string]any{"type": "string", "description": "URL to forward"},
			}),
		},
	}
	findings := Run(allTools)
	if len(findings) == 0 {
		t.Error("expected cross-server findings for multi-server config")
	}
}

func TestEveryChainHasValidContent(t *testing.T) {
	allTools := map[string][]mcp.Tool{
		"fs": {
			makeTool("read", "read file returning text", map[string]any{
				"file": map[string]any{"type": "string"},
			}),
		},
		"net": {
			makeTool("get", "GET a URL returning text", map[string]any{
				"url": map[string]any{"type": "string"},
			}),
		},
	}
	g := buildGraph(allTools)
	chains := detectCompositionChains(g)
	for _, c := range chains {
		if c.Server == "" {
			t.Error("chain finding has empty server")
		}
		if c.Severity != "MEDIUM" && c.Severity != "INFO" {
			t.Errorf("unexpected severity: %s", c.Severity)
		}
		if c.Type != "cross-server" {
			t.Errorf("unexpected type: %s", c.Type)
		}
	}
}
