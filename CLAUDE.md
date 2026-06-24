This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build, test, lint

Use `just`, not raw go commands.

| Command          | Does                                                                    |
| ---------------- | ----------------------------------------------------------------------- |
| `just install`   | Install golangci-lint v2.9.0 + goimports                                |
| `just build`     | `go build ./...`                                                        |
| `just test`      | `go test` (pass args for specific tests)                                |
| `just test-all`  | `go test ./...` (full suite, slow — run separately)                     |
| `just fmt`       | goimports on all `.go` files                                            |
| `just fix`       | `go fix ./...`                                                          |
| `just vet`       | `go vet ./...`                                                          |
| `just lint`      | golangci-lint (21 linters, 70-line funlen, 120-col lll)                 |
| `just loc-check` | 500-line file limit on changed files                                    |
| `just check`     | Fast pipeline: fmt → fix → tidy → vet → build → loc-check → lint (no tests) |

## Architecture

`mcp-audit` — MCP ecosystem security auditor. Single Go binary, stdlib-first.

Three‑phase pipeline: **discover** configs → **scan** statically (typosquat) → **probe** dynamically (SSRF).

### Packages

- `cmd/mcp-audit/` — CLI entry point. Subcommands: `scan`, `static`, `probe`, `watch`, `proxy`, `trust`, `upload`, `version`. Uses Cobra for command structure. Also contains unit tests for CLI logic.
- `e2e/` — end-to-end tests (package `e2e_test`). Builds binary from `cmd/mcp-audit` and exercises it via subprocess.
- `internal/config/` — discovers MCP config files across 6 AI tools. `discover.go` + `parser.go` dispatch to `parseMcpServers` or `parseContinue`.
- `internal/scanner/` — `static.go` runs typosquat checks via embedded package lists. `dynamic.go` does direct HTTP probes + MCP tool‑call probes against internal endpoints.
- `internal/mcp/` — MCP client wrapping the official MCP Go SDK (`github.com/modelcontextprotocol/go-sdk`).
- `internal/report/` — table (colorized TTY), JSON, SARIF output.
- `pkg/levenshtein/` — single‑row DP edit distance.

### Data flow

```
runStatic
  → config.Discover()
  → checkTyposquat() per server
  → report.Write()

runProbe
  → config.Discover()
  → direct HTTP probes (14 internal targets)
  → MCP handshake + tools/list (errgroup, 10 concurrent)
  → tools/call with crafted args
  → response analysis (regex for creds/internal content)
```

## Severity model

`SevCritical` → `SevHigh` → `SevMedium` → `SevLow` → `SevInfo` → `SevPass`.

CRITICAL when credentials or internal data returned. HIGH when internal content leaked. MEDIUM when connection to internal target blocked. LOW for open redirects without content. INFO for typosquat warnings or dry‑run. PASS otherwise.

Exit codes: 0 = clean, 1 = CRITICAL/HIGH found, 2 = scan error.

## Standards

- **Zero comments** — no doc comments, no inline comments.
- **No external dependencies** — stdlib only. Exceptions: `golang.org/x/sync/errgroup`, `golang.org/x/term`, `github.com/spf13/cobra`, `github.com/hashicorp/go-set`, `github.com/modelcontextprotocol/go-sdk`.
- **500‑line file limit** — enforced by `just loc-check`.
- **70‑line function limit** — enforced by `funlen` linter.
- **120‑char line limit** — enforced by `lll` linter.
- **Use `any`, not `interface{}`** — enforced by `modernize`.
- **No named return values** — never name return parameters. Enforced by `nakedret` linter.
- **`//go:embed` directives** kept — compiler pragmas, not comments.
- **Prefer trusted packages over bespoke implementations** — When a well-maintained, widely-used package provides the needed functionality (e.g., MCP Go SDK, Cobra, go-set), use it instead of building custom solutions. Bespoke implementations should only be created when existing packages don't meet specific requirements.
- **Run `just check` every turn that edits code** — zero lint issues before reporting done. Tests are excluded from `check` due to slow e2e suites; run `just test-all` separately when verifying test correctness.

## OpenSpec

- When creating or updating an OpenSpec proposal, always check whether the work belongs under an existing umbrella spec before introducing a new capability.
- If the proposal changes an existing part of the system, update the existing spec instead of creating a parallel one.
- Only create a new OpenSpec capability when the change documents a genuinely new part of the system not covered by any current umbrella.
- Current umbrella specs: `static-config-scanning`, `typosquat-detection`, `dynamic-ssrf-probing`, `report-formatting`.
