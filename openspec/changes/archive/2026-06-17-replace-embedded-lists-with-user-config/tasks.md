## 1. Remove embedded list infrastructure

- [x] 1.1 Delete `typosquat.go`, `known_legitimate.txt`, `known_malicious.txt` — remove `//go:embed` directives and `init()`-based list parsing

## 2. Create trust config system

- [x] 2.1 Create `internal/config/trust.go` with `TrustConfig` JSON struct (embedded `TrustScope`), `LoadTrust(path string)` function using `encoding/json`
- [x] 2.2 Add `DefaultTrustPath()` returning `~/.config/mcp-audit/trust.json`
- [x] 2.3 Add `ScopeFor(serverName, toolName string) TrustScope` method with server > tool > global resolution

## 3. Update typosquat detection

- [x] 3.1 Create `internal/scanner/scanner.go` with `Scanner` struct, `NewScanner()`, `SetTrustConfig(path)`
- [x] 3.2 Replace `RunStatic()` with `Scanner.Static()` method using `s.TrustConfig`
- [x] 3.3 Rewrite `checkTyposquat` to use resolved trust scope via `tc.ScopeFor(srv.Name, srv.Tool)`

## 4. Wire CLI flag

- [x] 4.1 Add `--trust-config <path>` flag to `flags` struct in main.go, thread through `runStaticAction` and `runProbe`
- [x] 4.2 Explicit `--trust-config` path that fails to load exits with code 2; default path failures are silent

## 5. Trust config in dynamic probing

- [x] 5.1 Replace `RunDynamic(DynamicConfig)` with `Scanner.Probe(dryRun bool)` using `s.Probes`/`s.AllowHosts`/`s.BlockHosts`
- [x] 5.2 Filter probed servers by trust config: servers with blocked scope entries are excluded from probing

## 6. Extract analysis functions

- [x] 6.1 Move probe response analysis to `internal/scanner/analysis.go` to keep `dynamic.go` under 500 lines
