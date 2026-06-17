## 1. Tool relationship graph

- [ ] 1.1 Create `internal/analysis/graph.go` — `ToolNode` struct, `ToolGraph` with adjacency list
- [ ] 1.2 Implement `BuildGraph(allTools map[string][]mcp.Tool)` — classify input/output types from InputSchema
- [ ] 1.3 Classify types: file-path, url, text, json, binary, command from property names and descriptions

## 2. Composition chain detection

- [ ] 2.1 Create `internal/analysis/chains.go` — DFS from each data-access node to find paths to network-access nodes
- [ ] 2.2 Classify tools as data-access (filesystem, database, env) vs network-access (URL fetch, HTTP, socket)
- [ ] 2.3 Report chains at MEDIUM severity with the full path in finding text

## 3. Confused deputy detection

- [ ] 3.1 Implement `detectConfusedDeputy(tool mcp.Tool) bool` — match description keywords and URL-type params
- [ ] 3.2 Flag URL-forwarding tools adjacent to network-access tools
- [ ] 3.3 Report at MEDIUM severity with tool name and server

## 4. Capability adjacency scoring

- [ ] 4.1 Compute adjacency score per server: sum of risk weights of neighboring servers' capabilities
- [ ] 4.2 Risk weights: filesystem=3, shell=5, network=2, database=2, unknown=1
- [ ] 4.3 Report elevated scores (>5) as INFO with capability breakdown

## 5. Integration

- [ ] 5.1 Collect all tools from all servers after probe phase in `runMCPProbes`
- [ ] 5.2 Run cross-server analysis before report output
- [ ] 5.3 Add `--cross-server-analysis` / `--no-cross-server-analysis` flags

## 6. Tests

- [ ] 6.1 Test graph building with 2-server, 3-server, and single-server scenarios
- [ ] 6.2 Test chain detection: filesystem→network chain found, no chain in safe config
- [ ] 6.3 Test confused deputy detection with crafted tool descriptions
- [ ] 6.4 Test adjacency scoring with varied capability combinations
- [ ] 6.5 Test flag toggle suppresses cross-server findings
