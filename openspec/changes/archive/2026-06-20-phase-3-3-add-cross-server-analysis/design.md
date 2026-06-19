## Context

Tool is single-server. IEEE S&P 2026 proves cross-server chains succeed in 9/10 cases. MCP protocol lacks isolation and least-privilege. Need to model server interactions.

## Goals

Build tool relationship graph, detect composition chains, identify confused deputy patterns, model capability adjacency, flag cross-server risk.

## Decisions

### Capability adjacency model

Classify each tool's input and output types from InputSchema: `file-path`, `url`, `text`, `json`, `binary`, `command`. Build adjacency matrix: if server A produces `text` and server B accepts `url`, flag as potential URL injection chain.

### Composition chain detection

DFS on the relationship graph from each network-capable tool. If path exists from data-access tool → network-access tool, flag the chain. Chains >3 hops are INFO only (attack complexity correlates with chain length).

### Confused deputy: tool that forwards URLs

If tool A's description/schema suggests it forwards URL arguments to another tool or service, and server B has a URL-fetch tool, flag as potential confused deputy. Detect via description keyword matching ("fetch", "download", "get from URL") combined with URL-type input parameters.

### Implementation: in-memory graph, built per scan

No persistence needed. After all servers' tools are collected via ListTools, build graph in memory. Run analysis algorithms. Report findings. ~200 lines of Go.

## Risks

- **False positives on legitimate chains** → Chained tools are common (filesystem → search → display). Mitigation: flag as MEDIUM, not HIGH. User reviews chains.
- **Schema-based detection is imprecise** → InputSchema doesn't always reveal actual data flow. Mitigation: acknowledge as heuristic layer.
