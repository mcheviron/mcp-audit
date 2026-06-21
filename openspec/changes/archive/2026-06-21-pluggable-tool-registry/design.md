## Context

`internal/config/discover.go` has an `init()` function that populates an unexported `registry []ToolParser` with exactly 6 hardcoded entries. `Discover()` iterates only this registry. The `ToolParser` struct is unexported. To add a new tool, developers must modify Go source in this init block. There is no runtime extension mechanism — no config file, no CLI flag, no env var.

The MCP ecosystem uses two config formats: JSON (13+ tools) and TOML (Codex CLI exclusively). mcp-audit has zero TOML parsing capability — grep confirms no `toml` references exist in the codebase.

## Goals / Non-Goals

**Goals:**
- Export `ToolParser` struct and `RegisterTool` function for programmatic extension
- Add a `Format` field to `ToolParser` (`"json"` or `"toml"`) with runtime dispatch between `parseMcpServers` (JSON) and `parseCodexToml` (TOML)
- Load user-defined tools from `~/.config/mcp-audit/tools.json` and merge with built-in defaults
- Implement a TOML parser for Codex CLI's `[mcp_servers]` config format
- Add `--tools-config` CLI flag for custom registry file path

**Non-Goals:**
- YAML, JSONC, or other formats
- Remote registry fetching
- Plugin directory with downloadable parsers
- Per-tool parser plugins (only JSON/TOML dispatch needed)

## Decisions

**Decision: BurntSushi/toml over manual TOML parser**
- Rationale: BurntSushi/toml is the de facto standard Go TOML library, pure Go with no transitive deps, matches mcp-audit's stdlib-first philosophy. Alternative: writing a TOML parser from scratch — rejected due to complexity and potential for bugs. Alternative: using a different TOML library (pelletier/go-toml) — rejected because BurntSushi/toml has broader adoption and v1 API stability.
- The dependency is added to `go.mod` only; no other external deps are introduced.

**Decision: JSON for tools registry format over TOML**
- Rationale: mcp-audit's existing user config file is JSON. Consistency with the project's own config format is more important than matching Codex's TOML. Users editing mcp-audit config are already comfortable with JSON.
- The registry file schema is a simple JSON object with a `"tools"` array. Each tool entry has `name`, `format`, `server_key`, and platform-specific `paths`.

**Decision: Merge user tools with built-in; user wins on conflict**
- Rationale: If a user registers a tool with the same `name` as a built-in, their definition takes precedence. This allows users to override broken built-in paths without waiting for a release.

**Decision: Format dispatch via `Parse` function selector**
- Rather than a generic `Format` field that dynamically chooses a parser, we keep the existing `Parse func([]byte) ([]ServerEntry, error)` field. The `Format` field is metadata used during registration. For JSON tools, the registry auto-assigns `parseMcpServers` (or `parseContinue` / `parseOpenCode` for those special formats). For TOML tools, it assigns `parseCodexToml`. This keeps the parser selection explicit and testable.

## Risks / Trade-offs

- **TOML parsing adds a dependency** → Mitigation: BurntSushi/toml is pure Go, stdlib-compatible, widely trusted. If the dependency becomes problematic, the TOML format used by Codex is simple enough to hand-parse ~50 lines of Go.
- **User tools.json could break discovery** → Mitigation: On load error, log a warning and continue with built-in tools only. Malformed tools.json never crashes mcp-audit.
- **Tool name collisions** → Mitigation: User tools override built-in tools with the same name. A warning is logged when this happens.
