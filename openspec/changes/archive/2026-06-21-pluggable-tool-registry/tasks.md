## 1. Export ToolParser and add Format field

- [x] 1.1 Export `ToolParser` struct and `ToolParserFormat` type from `internal/config/types.go`
- [x] 1.2 Add `Format` field (`"json"` | `"toml"`) to `ToolParser`
- [x] 1.3 Export `RegisterTool(tp ToolParser)` function that appends to the registry
- [x] 1.4 Add `GetRegistry() []ToolParser` for reading the merged registry
- [x] 1.5 Run `just build` and `just test` to verify no regressions

## 2. Add TOML config parsing

- [x] 2.1 Add `github.com/BurntSushi/toml` to `go.mod`
- [x] 2.2 Create `internal/config/parser_toml.go` with `parseCodexToml(data []byte) ([]ServerEntry, error)`
- [x] 2.3 Implement `[mcp_servers.<name>]` section parsing, mapping TOML keys to `ServerEntry` fields
- [x] 2.4 Add unit tests in `internal/config/parser_toml_test.go` for stdio, HTTP, auth, env, malformed, empty
- [x] 2.5 Handle `bearer_token_env_var` resolution from environment

## 3. Runtime parser dispatch

- [x] 3.1 Add `resolveParse(format string, explicit Parse) ParseFunc` that selects parser by format
- [x] 3.2 Update `init()` in `discover.go` to call `initRegistry()` that sets Format on each built-in ToolParser
- [x] 3.3 Update `Discover()` to use `resolveParser(tp.Format, tp.Parse)` -- verify Format-based dispatch works end-to-end

## 4. User tools config file loading

- [x] 4.1 Define JSON schema for `tools.json` in `internal/config/tools_loader.go` (documented as structs)
- [x] 4.2 Create `LoadUserTools(path string) ([]ToolParser, error)` in `internal/config/tools_loader.go`
- [x] 4.3 Merge user tools with built-in registry in `InitRegistry()` -- user wins on name conflict, log warning
- [x] 4.4 Add `--tools-config` flag to `parseFlags()` in `cmd/mcp-audit/main.go`
- [x] 4.5 Wire `--tools-config` through to scanner configuration via `config.InitRegistry(f.toolsConfig)`
- [x] 4.6 Test: malformed tools.json logs warning and continues; missing tools.json is no-op

## 5. Codex CLI as built-in tool

- [x] 5.1 Add Codex CLI `ToolParser` entry to `initRegistry()` with `Format: FormatTOML`, platform paths
- [x] 5.2 Add macOS path: `~/Library/Application Support/Codex/config.toml`
- [x] 5.3 Add Linux path: `~/.codex/config.toml`
- [x] 5.4 Verify discover-skip when TOML parser unavailable (graceful degradation via resolveParser)

## 6. End-to-end validation

- [x] 6.1 Run `just check` -- zero lint issues
- [x] 6.2 Run `go test ./...` -- all tests pass
- [x] 6.3 Run `just build` -- binary builds with new dependency
- [x] 6.4 Manual test: create a `tools.json` with one custom tool, verify it appears in `static` output
- [x] 6.5 Manual test: create a sample `config.toml`, run `static`, verify Codex servers discovered
