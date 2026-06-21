## 1. GitHub Copilot CLI support

- [x] 1.1 Add `ToolParser` entry for `"copilot-cli"` with paths to `~/.copilot/mcp-config.json` (all platforms)
- [x] 1.2 Use `parseMcpServers` as parser
- [x] 1.3 Add unit test verifying Copilot config file parsing

## 2. Claude Code CLI support

- [x] 2.1 Add `ToolParser` entry for `"claude-code"` with paths to `.mcp.json` (project) and `~/.claude/mcp.json` (global)
- [x] 2.2 Use `parseMcpServers` as parser
- [x] 2.3 Add unit test verifying Claude Code CLI config parsing from both paths

## 3. Codex CLI support

- [x] 3.1 Add `ToolParser` entry for `"codex"` with `Format: "toml"`, platform paths
- [x] 3.2 Gate on TOML parser availability -- log debug message and skip if not registered
- [x] 3.3 Add unit test: Codex entry present in registry even when TOML parser absent
- [x] 3.4 Verify graceful degradation when `pluggable-tool-registry` not applied

## 4. Gemini CLI / Antigravity support

- [x] 4.1 Add `ToolParser` entry for `"gemini"` with paths to `.mcp.json` and `~/.gemini/settings.json`
- [x] 4.2 Implement `parseGeminiSettings(data []byte) ([]ServerEntry, error)` in `parser.go`
- [x] 4.3 Handle nested `mcp.mcpServers` key detection -- check both top-level and nested
- [x] 4.4 Add unit test for Gemini settings.json with both flat and nested mcpServers

## 5. Cline / Roo Code support

- [x] 5.1 Add `ToolParser` entry for `"cline-roo"` with VS Code extension storage paths per platform
- [x] 5.2 macOS: `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`
- [x] 5.3 Linux: `~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`
- [x] 5.4 Add unit test verifying Cline config parsing

## 6. Zed support

- [x] 6.1 Add `ToolParser` entry for `"zed"` with path to `~/.config/zed/settings.json`
- [x] 6.2 Implement key variant detection -- check `"mcp_servers"` (underscore) and `"mcpServers"` (camelCase)
- [x] 6.3 Add unit test for both key variants

## 7. Validation

- [x] 7.1 Run `just check` -- zero lint issues, zero new deprecation warnings
- [x] 7.2 Run `go test ./...` -- all tests pass including new tool-specific tests
- [x] 7.3 Manual test: verify each new tool appears in `prospector suggest` tool list (count = 12)
