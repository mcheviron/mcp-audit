## Why

mcp-audit's tool registry is hardcoded in an unexported `init()` block in `internal/config/discover.go`. Adding support for a new AI tool requires modifying Go source code, recompiling, and releasing a new binary. The MCP ecosystem is expanding rapidly — Codex CLI (TOML format), Gemini CLI, Antigravity, and others have launched since mcp-audit's initial design. Codex in particular uses TOML for MCP configuration, a format mcp-audit has zero support for. Users need a self-service mechanism to register new tools without waiting for upstream releases.

## What Changes

- Add a `Format` field to `ToolParser` (`"json"` | `"toml"`) with runtime parser dispatch
- Add TOML config parsing capability via a new `parseCodexToml` parser in `internal/config/`
- Make the tool registry extensible: load user-defined tools from `~/.config/mcp-audit/tools.json`
- Export `ToolParser` and `RegisterTool` so external Go packages can register tools programmatically
- Add `--tools-config` CLI flag to specify a custom tools registry file path

## Capabilities

### New Capabilities

- `toml-config-parsing`: Parse MCP server configurations from TOML-format files, extracting server entries with the same shape as JSON parsers produce
- `extensible-tool-registry`: Load tool parser definitions from an external JSON file, merge with built-in defaults, and validate at startup

### Modified Capabilities

- `static-config-scanning`: New requirement — the scanner SHALL merge built-in tool parsers with user-defined parsers from `~/.config/mcp-audit/tools.json` before config discovery. The `ToolParser` struct becomes exported.

## Non-goals

- Support for YAML, JSONC, or formats other than JSON and TOML
- Remote/URL-based tool registry fetching
- Plugin directory with downloadable parsers
- Project-scoped tool registration (that is `project-scoped-discovery`)

## Impact

- `internal/config/types.go`: Export `ToolParser`, `ToolParserFormat`, `RegisterTool`
- `internal/config/discover.go`: Replace `init()` with `initRegistry()`, merge external tools
- `internal/config/parser_toml.go`: New file, TOML parser using `BurntSushi/toml` (stdlib-compatible)
- `internal/configfile/config.go`: New `ToolsConfigPath` field
- `cmd/mcp-audit/main.go`: New `--tools-config` flag
- `go.mod`: New dependency `github.com/BurntSushi/toml`
