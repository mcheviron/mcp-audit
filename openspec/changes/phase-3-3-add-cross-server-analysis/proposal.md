## Why

The tool is strictly single-server: static.go checks one package at a time, dynamic.go probes one server at a time. IEEE S&P 2026 paper "Parasites in the Toolchain" proves multi-stage cross-server attacks succeed in 9 of 10 constructed chains. MCP lacks context-tool isolation and least-privilege enforcement at the protocol level. A server with read-only file access can feed data to a server with network access. Current tool can't detect or even model these relationships.

## What Changes

- Build tool relationship graph: which tools consume which types of data, which produce which types
- Detect composition chains: server A's output flows to server B's input → potential data exfiltration path
- Detect confused deputy: tool that takes a URL from one source and passes it to another server's network-access tool
- Flag cross-server tool chains at MEDIUM (potential) or HIGH (confirmed dangerous combination) severity
- Model capability adjacency: filesystem-access server next to network-access server = elevated risk
- `--cross-server-analysis` flag (default: on for `scan`, off for single-action commands)

## Capabilities

### New Capabilities

- `cross-server-analysis`: Multi-server tool relationship mapping, composition chain detection, confused deputy identification, and capability adjacency risk scoring.

## Impact

- `internal/analysis/` — new package: `graph.go` (tool relationship graph), `chains.go` (composition chain detection), `adjacency.go` (capability adjacency)
- `internal/scanner/dynamic.go` — collect all tools from all servers, pass to cross-server analysis
- `internal/scanner/static.go` — incorporate cross-server findings in static results
- `main.go` — `--cross-server-analysis` / `--no-cross-server-analysis` flags

## Non-Goals

- Runtime taint tracking (requires proxy mode, separate proposal)
- Formal verification of tool compositions
- Full data flow analysis with type inference — capability-level adjacency is sufficient for MVP
- Automated attack chain generation (red-team tool, not auditor scope)
