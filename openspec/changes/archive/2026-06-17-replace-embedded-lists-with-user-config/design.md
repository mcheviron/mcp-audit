## Context

`internal/scanner/typosquat.go` uses `//go:embed` to bake `known_legitimate.txt` (25 entries) and `known_malicious.txt` (13 entries) into the binary at compile time. `checkTyposquat` in `static.go` checks discovered packages against these lists and runs Levenshtein distance against the legitimate set.

This doesn't work for a real product: the lists are a snapshot that's stale immediately, 25 entries is a tiny fraction of the MCP ecosystem, and 13 hand-crafted typosquat variants are arbitrary. Organizations need to define their own trust boundaries — which MCP packages they've vetted and which misspellings they want to block.

## Goals / Non-Goals

**Goals:**
- Delete `typosquat.go`, `known_legitimate.txt`, `known_malicious.txt`, and the `//go:embed` mechanism
- Accept `--trust-config <path>` flag pointing to a JSON file with `trusted` and `blocked` arrays
- Default path: `~/.config/mcp-audit/trust.json` when `--trust-config` is omitted
- If no config file exists, skip typosquat entirely (return PASS with "no trust config loaded" note)
- JSON file uses `encoding/json` from stdlib — zero new dependencies
- Keep Levenshtein distance≤2 check against the user's `trusted` list

**Non-Goals:**
- YAML, TOML, or other config formats — JSON only, stdlib
- Fetching trust lists from URLs
- Per-tool or per-server trust scoping
- Automatic discovery of trust configs (scanning multiple paths)

## Decisions

### JSON config format

```json
{
  "trusted": ["@modelcontextprotocol/server-filesystem", "mcp-server-time"],
  "blocked": ["@modelcontextprotcol/server-filesystem"]
}
```

Both keys optional. Empty file, missing keys, or missing file all mean "no trust config." Stdlib `encoding/json` — no new dependency.

Alternative: plain text with section headers (`# trusted` / `# blocked`). Rejected — JSON is structured, familiar to users, and `encoding/json` is battle-tested. Text format with section headers is homegrown and fragile.

Alternative: YAML with `gopkg.in/yaml.v3`. Rejected — external dependency violates stdlib-first constraint. The config is a flat list of strings; JSON is sufficient.

### Config loading on every static scan, not at startup

`config.LoadTrust(path)` called from `RunStatic()`. Not cached globally. Users can edit the file between scans. The file is read once per scan invocation — negligible cost (<1ms for 100 entries).

### No trust config = skip typosquat, not error

Missing config is normal state for new users. Don't warn, don't error. Just report PASS with reason "no trust config loaded." Typosquat detection is only as good as the user's data — we provide the mechanism, they provide the lists.

### TrustConfig type lives in scanner package, not config

The trust config is a scanner concern (typosquat input), not a config discovery concern (MCP server metadata). Separate concerns. `internal/scanner/trust.go` holds the type, loader, and path resolution.

## Risks / Trade-offs

- **Users don't know about the feature** → Usage text mentions `--trust-config` flag; `mcp-audit static` output notes when no config is loaded
- **JSON syntax errors silently skip typosquat** → Parse errors are reported as INFO finding, not fatal — typosquat is defense-in-depth, not primary security boundary
- **Levenshtein threshold of 2 still produces false positives** → User can add known-false-positives to their `trusted` list. The threshold is tunable in code (constant), not yet user-configurable
