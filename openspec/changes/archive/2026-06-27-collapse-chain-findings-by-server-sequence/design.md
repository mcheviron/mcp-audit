## Context

`detectCompositionChains` in `internal/analysis/chains.go` uses `findPaths` (DFS up to depth 5) to enumerate every tool-level path from a data-access node to a net-access node. For each path, it emits a separate `Finding`. With 16 servers each exposing 5-50 tools, the total tool count is ~150-200 nodes. The graph edges connect any two nodes on different servers where `connects()` returns true — which is liberal: `text` or `json` output types connect to anything. This produces a dense graph where even a single 5-hop server sequence fans out into thousands of tool-level variants.

Real data from a probe run: 28,606 chain findings from 138 unique server sequences. Top sequences are permutations of datagouv, openaiDeveloperDocs, deepwiki, gh_grep.

## Goals / Non-Goals

**Goals:**
- Collapse tool-level chain paths to server-level findings inside `detectCompositionChains`
- Each unique server sequence produces exactly one finding
- Finding severity = maximum severity across all tool-level paths in the group
- Finding text names the server sequence with a count of tool-level paths
- Detail shows up to 3 example tool-level paths
- Total chain findings drop from 28,606 to ~140 for the same input

**Non-Goals:**
- Not changing `findPaths` graph traversal or depth limits
- Not changing `connects()` edge logic
- Not affecting `detectConfusedDeputy` or `computeAdjacencyScores`
- Not changing JSON/SARIF output format

## Decisions

**Decision: Group by server sequence string, not by equivalence class**

Server sequence key: `strings.Join(serverNames, " -> ")` where server names are extracted from tool-level paths via `strings.SplitN(toolRef, "/", 2)`. This is a simple string key, easy to test and debug.

Alternative: Bidirectional equivalence (A→B→A ≡ B→A→B). Rejected — direction matters for exfiltration (data flows from left to right). A chain ending at a network server on the right is different from one ending at a database server.

**Decision: Max severity in group, not average or mode**

If any path in the group has chain length > 5 (CRITICAL), the group finding is CRITICAL. This is conservative — we never under-report. The count in the finding text tells the user how many paths exist so they can assess scope.

**Decision: 3 example paths in Detail, not all**

Showing all paths defeats the purpose. Three examples give the user enough context to understand the chain without overwhelming them. The finding text already says "5,094 tool-level paths found" so they know the scale.

**Decision: Keep existing severity tiers based on chain length**

Current mapping: ≤3 hops → MEDIUM, 4-5 hops → HIGH, >5 hops → CRITICAL. This stays. Server-level grouping means a group with mixed 3-hop and 5-hop paths gets CRITICAL (max).

## Risks / Trade-offs

- Same-server tool chaining is lost: two tools on the same server that chain are NOT separated since `connects()` skips same-server edges. → Already the case today, no regression.

- A single-server sequence finding with 1,000 tool-level paths might obscure a genuinely dangerous specific path. → Mitigated by 3 example paths in Detail. If user needs full enumeration, they can run with `--verbose` to get debug logs, or we can add a `--full-chains` flag later.

- The finding text format changes from tool-level to server-level. This is a display change, not a data model change. JSON/SARIF output includes the same fields; only the string content differs. Users parsing `--format json` output may need to update field expectations. → Acceptable: the old format was unusable due to volume.
