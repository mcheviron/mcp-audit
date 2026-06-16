## Context

`build-mcp-auditor` delivered a working three-phase pipeline (discover → static → probe). The implementation favored shipping over polish. Five shortcuts remain:

1. `ConfigPath` field is populated during discovery but never surfaced in reports
2. `AllowHosts`/`BlockHosts` in `DynamicConfig` are parsed but never filter probes
3. Direct HTTP probes run sequentially (N servers × 14 targets = linear wall-clock)
4. `mcp.Client` is a concrete struct — tests call `httptest` but callers couple to HTTP
5. `config.Discover()` has 6 hardcoded parser calls; adding a 7th tool requires editing the function
6. `probeTargets` is a package `var` — changing targets requires recompilation

## Goals / Non-Goals

**Goals:**
- Wire `AllowHosts`/`BlockHosts` into probe filtering (spec already requires it)
- Surface `ConfigPath` in table/JSON/SARIF output
- Parallelize direct HTTP probes with bounded concurrency
- Extract `Transporter` interface from `mcp.Client`
- Replace hardcoded parser dispatch with a registry
- Accept `--targets` flag to override probe target list

**Non-Goals:**
- Changing the MCP protocol wire format
- Adding new probe target categories (cloud, docker, etc.)
- Dynamic target list loading from file
- Plugin system for parsers — just a mechanical registry, same package

## Decisions

### Concurrent direct probes: errgroup with limit 10

Same pattern already used for MCP probes (`runMCPProbes`). Direct HTTP probes are independent — no shared state mutation until collection. Lifting the `http.Client` to one per call site (already done) makes this safe.

Alternative considered: plain goroutines + WaitGroup. Rejected — errgroup gives us context cancellation for free and matches existing code style.

### Transport interface: single-method interface per operation

Instead of one `Transporter` interface with all methods, define `Client` as an interface with `Initialize`, `ListTools`, `CallTool`. The existing `mcp.Client` struct satisfies it automatically. `NewClient` returns the interface type.

```go
type Client interface {
    Initialize(ctx context.Context) (*InitializeResult, error)
    ListTools(ctx context.Context) (*ListToolsResult, error)
    CallTool(ctx context.Context, name string, args map[string]any) (*CallToolResult, error)
}
```

Alternative: Keep concrete struct, use `httptest` in tests. Already works today — but callers who want to mock MCP for unit tests can't. Interface costs nothing at runtime.

### Parser registry: slice of structs

A `ToolParser` struct holds tool name, config paths (per-platform), and a parse function. `Discover()` iterates the registry. Adding OpenCode was 20 lines inside the function body — registry makes it 4 lines in the registry init.

```go
type ToolParser struct {
    Name  string
    Paths func() []string
    Parse func(path string, cfg *Config) error
}
```

Alternative: map of funcs. Slice gives deterministic ordering for tests.

### Configurable targets: `--targets` flag, comma-separated

Default to the built-in 14 targets. `--targets` overrides entirely (not appends). Simple, predictable.

Alternative: `--targets-file` for file-based lists. Not needed yet — 14 targets fit in a CLI flag.

## Risks / Trade-offs

- **Direct probe concurrency changes output order** → Results already aggregated by severity in summary; order not contractual. Table output may shuffle — acceptable.
- **Interface extraction is zero-cost at runtime** → Interface satisfaction checked at compile time (`var _ Client = (*client)(nil)`)
- **Registry makes init order visible** → Registry populated at package init or variable init; no hidden loading. Tests can register fake parsers.
- **`--targets` overrides don't persist** → Users with custom targets must pass the flag each invocation. Mitigation: if demand arises, add config file support later.
