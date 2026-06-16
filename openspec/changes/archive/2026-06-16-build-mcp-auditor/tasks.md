## 1. Project Scaffold

- [x] 1.1 Create Go module structure: `main.go`, `cmd/`, `internal/`, `pkg/` directories
- [x] 1.2 Set up `main.go` with cobra CLI root command and subcommand dispatch (`scan`, `static`, `probe`, `version`)
- [x] 1.3 Add `go.mod` with Go 1.26 and `golang.org/x/sync/errgroup` as sole external dependency

## 2. Levenshtein Distance

- [x] 2.1 Implement `pkg/levenshtein/distance.go`: standard DP edit-distance with insert/delete/substitute cost 1
- [x] 2.2 Write table-driven tests for identical strings, single char diff, empty string, multi-char diff

## 3. Config File Discovery

- [x] 3.1 Implement `internal/config/discover.go`: cross-platform config file resolver (XDG, home dir, platform defaults)
- [x] 3.2 Implement parsers for each tool: `claude.go`, `cursor.go`, `windsurf.go`, `vscode.go`, `continue.go`
- [x] 3.3 Write tests with fixture JSON configs for each tool (valid config, empty config, malformed config)

## 4. Static Scanner

- [x] 4.1 Implement `internal/scanner/static.go`: orchestrates config discovery, parses all 5 tools, extracts server entries
- [x] 4.2 Implement `internal/scanner/typosquat.go`: loads embedded known-legitimate and known-malicious lists, runs Levenshtein check on each package name
- [x] 4.3 Embed legitimate/malicious package lists as `//go:embed` files in `internal/scanner/`

## 5. Report Formatting

- [x] 5.1 Implement `internal/report/format.go`: unified `Finding` struct with severity enum, server name, finding type, description, detail
- [x] 5.2 Implement `internal/report/table.go`: terminal table output via `text/tabwriter` with severity columns
- [x] 5.3 Implement `internal/report/json.go`: JSON output with stdout (data) / stderr (progress) separation
- [x] 5.4 Implement `internal/report/sarif.go`: SARIF v2.1.0 output with severity mapping and file writing

## 6. MCP Protocol Client

- [x] 6.1 Implement `internal/mcp/protocol.go`: JSON-RPC 2.0 message types (`initialize`, `tools/list`, `tools/call` request/response structs)
- [x] 6.2 Implement `internal/mcp/transport.go`: HTTP transport with POST to MCP endpoint, JSON serialization, 5s timeout
- [x] 6.3 Write integration tests with `net/http/httptest` mock MCP server

## 7. Dynamic SSRF Prober

- [x] 7.1 Implement `internal/scanner/dynamic.go`: SSRF probe orchestrator with target IP list (127.0.0.1, 169.254.169.254, metadata.google.internal, [::1], 0.0.0.0, private ranges)
- [x] 7.2 Implement response analysis: cloud metadata detection (AWS key patterns, GCP token patterns), redirect chain tracking, internal IP detection in response body
- [x] 7.3 Implement safety controls: max 10 concurrent probes via errgroup, 100ms inter-probe delay, 5s per-probe timeout, 4KB response truncation
- [x] 7.4 Implement opt-in gating: `scan` prompts for confirmation, `probe` runs directly, `--dry-run` prints without connecting

## 8. CLI Integration

- [x] 8.1 Wire `scan` subcommand: runs static scanner, prints results, prompts for dynamic probing, runs prober, prints combined results
- [x] 8.2 Wire `static` subcommand: config scan only, table/JSON/SARIF output
- [x] 8.3 Wire `probe` subcommand: dynamic probing only, `--dry-run`, `--allow-hosts`, `--block-hosts` flags
- [x] 8.4 Implement exit codes: 0 clean, 1 CRITICAL/HIGH found, 2 scan error

## 9. Polish

- [x] 9.1 Add colorized terminal output (CRITICAL=red, HIGH=yellow, MEDIUM=cyan, LOW=blue, INFO=dim, PASS=green) — TTY-detected only
- [x] 9.2 Write README.md with install instructions (`go install`), usage examples, example output
- [x] 9.3 Set up goreleaser config for cross-compiled releases (macOS arm64/amd64, Linux arm64/amd64)
- [x] 9.4 Create GitHub Actions workflow: lint, test, goreleaser on tag
