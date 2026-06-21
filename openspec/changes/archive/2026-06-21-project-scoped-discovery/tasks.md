## 1. Add Scope field to data model

- [x] 1.1 Add `Scope string` field to `ServerEntry` in `internal/config/types.go` (`"global"` | `"project"`)
- [x] 1.2 Add `Scope string` field to `Config` in `internal/config/types.go`
- [x] 1.3 Run `just build` to verify compilation with new fields

## 2. Implement upward directory walk

- [x] 2.1 Add `walkProjectConfigs(cwd string, tp ToolParser) ([]string, error)` to `discover.go`
- [x] 2.2 Walk from cwd to root (`/`), checking each ancestor for project config files from `tp.Paths`
- [x] 2.3 Stop at first config-bearing directory per tool
- [x] 2.4 Add unit test: config found 1 level up, config at cwd, config at root, no config anywhere

## 3. Update Discover() to support project scope

- [x] 3.1 Change `Discover()` signature to `Discover(cwd string) []Config`
- [x] 3.2 When cwd is non-empty, walk for project configs before checking global paths
- [x] 3.3 For each tool, merge project + global configs: project servers take precedence for same name
- [x] 3.4 Annotate each `ServerEntry.Scope` as `"global"` or `"project"`
- [x] 3.5 Annotate each `Config.Scope` as `"project"` if any server is project-scoped, otherwise `"global"`
- [x] 3.6 Update all callers of `Discover()` -- `scanner.go`, watcher

## 4. Add CLI flags

- [x] 4.1 Add `--project-dir` flag to `parseFlags()` (default: current working directory)
- [x] 4.2 Add `--no-project-config` flag to `parseFlags()`
- [x] 4.3 Wire flags through to `Scanner` and `Discover()`
- [x] 4.4 When `--no-project-config` is set, pass empty string to `Discover("")`

## 5. Update daemon/watch mode

- [x] 5.1 Update `watcher.go` to watch project-scoped config paths in addition to global paths
- [x] 5.2 When project config changes, re-scan with updated project scope

## 6. Report display of scope

- [x] 6.1 In table output, append scope to ConfigPath when scope is project: `"server (project: /path/.mcp.json)"`
- [x] 6.2 In JSON output, include `scope` field on each finding

## 7. Validation

- [x] 7.1 Run `just lint` -- zero lint issues
- [x] 7.2 Run `go test ./...` -- all tests pass
- [x] 7.3 Manual test: create `.mcp.json` in current dir, run `static`, verify project scope annotated
- [x] 7.4 Manual test: run with `--no-project-config`, verify only global configs discovered
