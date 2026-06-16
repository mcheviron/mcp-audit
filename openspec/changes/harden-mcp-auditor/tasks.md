## 1. Wire dead fields

- [x] 1.1 Surface ConfigPath in report output — add ConfigPath column to table (when non-empty), field to JSON entries, and property to SARIF results
- [x] 1.2 Filter probe targets by AllowHosts/BlockHosts — add `filterTargets` function, call it before probing in `runDirectProbes` and `runMCPProbes`

## 2. MCP transport interface

- [x] 2.1 Extract `Client` interface with Initialize/ListTools/CallTool — rename concrete type to `httpClient`, export `Client` interface, add compile-time assertion

## 3. Parser registry

- [x] 3.1 Define `ToolParser` struct — Name, Paths func, Parse func — in config package
- [x] 3.2 Convert `Discover()` to registry iteration — populate registry slice, replace hardcoded calls with loop over registered parsers

## 4. Concurrent direct probes

- [x] 4.1 Replace sequential loop in `runDirectProbes` with errgroup-based concurrency — same 10-limit pattern as `runMCPProbes`

## 5. Configurable probe targets

- [x] 5.1 Add `--targets` comma-separated flag to CLI — parse in main.go, thread through `DynamicConfig`, override `probeTargets` when set
