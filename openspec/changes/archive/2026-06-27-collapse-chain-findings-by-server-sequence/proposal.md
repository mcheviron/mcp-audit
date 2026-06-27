## Why

`detectCompositionChains` in `internal/analysis/chains.go` enumerates every tool-level path through the cross-server graph, producing one finding per unique tool sequence. With 16 servers each exposing 5-50 tools, the path space explodes: a single 5-hop server sequence like `datagouv -> openaiDeveloperDocs -> datagouv -> openaiDeveloperDocs -> datagouv` generates 12,000+ tool-level variants. A recent probe run produced 28,606 chain findings from only 138 unique server sequences — a 207:1 noise ratio. Real findings (adversarial probe detections, SSRF blocks) are buried under thousands of near-identical chain reports nobody can review.

## What Changes

- Group composition chain findings by server sequence (e.g., `datagouv -> openaiDeveloperDocs -> datagouv`) instead of tool sequence (e.g., `datagouv/search_datasets -> openaiDeveloperDocs/search_openai_docs -> datagouv/get_dataservice_info`)
- Each unique server sequence produces one finding with severity set to the maximum across all tool-level paths in that group
- The finding description names the server sequence and counts the tool-level paths
- The detail field shows up to 3 example tool-level paths so the user can investigate specific tools
- No change to path discovery — `findPaths` still explores the full graph. Only the **output** changes: paths are aggregated before findings are emitted.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `cross-server-analysis`: Composition chain findings are now grouped by server sequence instead of enumerated per tool path. Severity is determined by the longest chain in the group, not per-path. Finding text format changes from tool-level to server-level.

## Impact

- `internal/analysis/chains.go` — `detectCompositionChains` function: add grouping pass after path collection
- `internal/analysis/chains_test.go` — new test cases for grouping behavior
- `openspec/specs/cross-server-analysis/spec.md` — updated requirement for finding format
- No API changes, no new dependencies, no CLI flag changes

## Non-goals

- Not changing path discovery algorithm or depth limits
- Not changing confused deputy or adjacency score analysis (those don't explode)
- Not adding new CLI flags
- Not removing the `--no-cross-server-analysis` flag
