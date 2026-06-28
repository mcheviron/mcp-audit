package config

import (
	"os"
	"testing"

	"github.com/hashicorp/go-set"
)

func TestParseClaudeValid(t *testing.T) {
	servers, err := parseMCPServers(mustRead(t, "claude_valid.json"), "claude")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 3 {
		t.Fatalf("expected 3 servers, got %d", len(servers))
	}

	fs := findServer(t, servers, "filesystem")
	if fs.Transport != "stdio" {
		t.Errorf("filesystem: expected stdio, got %s", fs.Transport)
	}
	if fs.Package != "@modelcontextprotocol/server-filesystem" {
		t.Errorf("filesystem: expected @modelcontextprotocol/server-filesystem, got %s", fs.Package)
	}
	if fs.Tool != "claude" {
		t.Errorf("filesystem: expected tool=claude, got %s", fs.Tool)
	}

	prospect := findServer(t, servers, "prospect")
	if prospect.Package != "prospect" {
		t.Errorf("prospect: expected package=prospect, got %s", prospect.Package)
	}

	remote := findServer(t, servers, "remote-api")
	if remote.Transport != "http" {
		t.Errorf("remote-api: expected http, got %s", remote.Transport)
	}
	if remote.URL != "http://localhost:3000/mcp" {
		t.Errorf("remote-api: expected url, got %s", remote.URL)
	}
}

func TestParseClaudeEmpty(t *testing.T) {
	servers, err := parseMCPServers(mustRead(t, "claude_empty.json"), "claude")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 0 {
		t.Errorf("expected 0 servers, got %d", len(servers))
	}
}

func TestParseClaudeMalformed(t *testing.T) {
	_, err := parseMCPServers(mustRead(t, "claude_malformed.json"), "claude")
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestParseContinueValid(t *testing.T) {
	servers, err := parseContinue(mustRead(t, "continue_valid.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(servers))
	}
	if servers[0].Transport != "stdio" {
		t.Errorf("server 0: expected stdio, got %s", servers[0].Transport)
	}
	if servers[0].Package != "@continuedev/mcp-server" {
		t.Errorf("server 0: expected @continuedev/mcp-server, got %s", servers[0].Package)
	}
	if servers[1].Transport != "http" {
		t.Errorf("server 1: expected http, got %s", servers[1].Transport)
	}
}

func TestParseContinueEmpty(t *testing.T) {
	servers, err := parseContinue(mustRead(t, "continue_empty.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 0 {
		t.Errorf("expected 0 servers, got %d", len(servers))
	}
}

func TestParseCursor(t *testing.T) {
	servers, err := parseMCPServers(mustRead(t, "cursor_valid.json"), "cursor")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
	if servers[0].Package != "mcp-server-time" {
		t.Errorf("expected mcp-server-time package, got %s", servers[0].Package)
	}
	if servers[0].Tool != "cursor" {
		t.Errorf("expected tool=cursor, got %s", servers[0].Tool)
	}
}

func TestParseWindsurf(t *testing.T) {
	servers, err := parseMCPServers(mustRead(t, "windsurf_valid.json"), "windsurf")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
	if servers[0].Package != "github.com/example/mcp-server@latest" {
		t.Errorf("expected go package, got %s", servers[0].Package)
	}
}

func TestParseVSCode(t *testing.T) {
	servers, err := parseMCPServers(mustRead(t, "vscode_valid.json"), "vscode")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
	if servers[0].Package != "my-mcp-package" {
		t.Errorf("expected my-mcp-package, got %s", servers[0].Package)
	}
}

func TestParseOpenCode(t *testing.T) {
	servers, err := parseOpenCode(mustRead(t, "opencode_valid.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 3 {
		t.Fatalf("expected 3 servers, got %d", len(servers))
	}

	prospector := findServer(t, servers, "prospector")
	if prospector.Transport != "stdio" {
		t.Errorf("prospector: expected stdio, got %s", prospector.Transport)
	}
	if prospector.Package != "prospect" {
		t.Errorf("prospector: expected prospect, got %s", prospector.Package)
	}
	if prospector.Tool != "opencode" {
		t.Errorf("prospector: expected tool=opencode, got %s", prospector.Tool)
	}

	deepwiki := findServer(t, servers, "deepwiki")
	if deepwiki.Transport != "http" {
		t.Errorf("deepwiki: expected http, got %s", deepwiki.Transport)
	}
	if deepwiki.URL != "https://mcp.deepwiki.com/mcp" {
		t.Errorf("deepwiki: expected url, got %s", deepwiki.URL)
	}

	filesystem := findServer(t, servers, "filesystem")
	if filesystem.Package != "@modelcontextprotocol/server-filesystem" {
		t.Errorf("filesystem: expected @modelcontextprotocol/server-filesystem, got %s", filesystem.Package)
	}
}

func TestParseClaudeEnvHeaders(t *testing.T) {
	data := []byte(`{
	  "mcpServers": {
	    "leaky": {
	      "command": "npx",
	      "args": ["-y", "pkg"],
	      "env": {"API_KEY": "sk-abc", "PORT": 8080, "DEBUG": true},
	      "headers": {"Authorization": "Bearer xyz"}
	    }
	  }
	}`)
	servers, err := parseMCPServers(data, "claude")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
	srv := servers[0]
	if srv.Env["API_KEY"] != "sk-abc" {
		t.Errorf("API_KEY env: got %q", srv.Env["API_KEY"])
	}
	if srv.Env["PORT"] != "8080" {
		t.Errorf("PORT env coerced: got %q", srv.Env["PORT"])
	}
	if srv.Env["DEBUG"] != "true" {
		t.Errorf("DEBUG env coerced: got %q", srv.Env["DEBUG"])
	}
	if srv.Headers["Authorization"] != "Bearer xyz" {
		t.Errorf("Authorization header: got %q", srv.Headers["Authorization"])
	}
}

func TestParseClaudeLegacyNoEnvHeaders(t *testing.T) {
	servers, err := parseMCPServers(mustRead(t, "claude_valid.json"), "claude")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, srv := range servers {
		if srv.Env != nil || srv.Headers != nil {
			t.Errorf("server %q: expected nil env/headers for legacy config", srv.Name)
		}
	}
}

func TestParseCopilotCli(t *testing.T) {
	servers, err := parseMCPServers(mustRead(t, "copilot_valid.json"), "copilot-cli")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(servers))
	}

	gh := findServer(t, servers, "github")
	if gh.Transport != "stdio" {
		t.Errorf("github: expected stdio, got %s", gh.Transport)
	}
	if gh.Package != "@copilot/mcp-server" {
		t.Errorf("github: expected @copilot/mcp-server, got %s", gh.Package)
	}
	if gh.Tool != "copilot-cli" {
		t.Errorf("github: expected tool=copilot-cli, got %s", gh.Tool)
	}

	api := findServer(t, servers, "api")
	if api.Transport != "http" {
		t.Errorf("api: expected http, got %s", api.Transport)
	}
	if api.URL != "https://api.copilot.github.com/mcp" {
		t.Errorf("api: expected url, got %s", api.URL)
	}
}

func TestParseClaudeCodeCli(t *testing.T) {
	servers, err := parseMCPServers(mustRead(t, "claude_code_valid.json"), "claude-code")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(servers))
	}

	prospector := findServer(t, servers, "prospector")
	if prospector.Transport != "stdio" {
		t.Errorf("prospector: expected stdio, got %s", prospector.Transport)
	}
	if prospector.Package != "prospector" {
		t.Errorf("prospector: expected prospector, got %s", prospector.Package)
	}
	if prospector.Tool != "claude-code" {
		t.Errorf("prospector: expected tool=claude-code, got %s", prospector.Tool)
	}

	fs := findServer(t, servers, "filesystem")
	if fs.Package != "@anthropic/mcp-server-filesystem" {
		t.Errorf("filesystem: expected @anthropic/mcp-server-filesystem, got %s", fs.Package)
	}
}

func TestParseGeminiTopLevel(t *testing.T) {
	servers, err := parseGeminiSettings(mustRead(t, "gemini_top_level.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}

	s := findServer(t, servers, "search")
	if s.Transport != "stdio" {
		t.Errorf("search: expected stdio, got %s", s.Transport)
	}
	if s.Package != "@google/mcp-server-search" {
		t.Errorf("search: expected @google/mcp-server-search, got %s", s.Package)
	}
	if s.Tool != "gemini" {
		t.Errorf("search: expected tool=gemini, got %s", s.Tool)
	}
}

func TestParseGeminiNested(t *testing.T) {
	servers, err := parseGeminiSettings(mustRead(t, "gemini_nested.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}

	s := findServer(t, servers, "code-assist")
	if s.Transport != "stdio" {
		t.Errorf("code-assist: expected stdio, got %s", s.Transport)
	}
	if s.Package != "github.com/google/mcp-server@latest" {
		t.Errorf("code-assist: expected github.com/google/mcp-server@latest, got %s", s.Package)
	}
	if s.Tool != "gemini" {
		t.Errorf("code-assist: expected tool=gemini, got %s", s.Tool)
	}
}

func TestParseGeminiEmpty(t *testing.T) {
	servers, err := parseGeminiSettings(mustRead(t, "gemini_empty.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 0 {
		t.Errorf("expected 0 servers, got %d", len(servers))
	}
}

func TestParseClineRoo(t *testing.T) {
	servers, err := parseMCPServers(mustRead(t, "cline_roo_valid.json"), "cline-roo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(servers))
	}

	mem := findServer(t, servers, "memory")
	if mem.Transport != "stdio" {
		t.Errorf("memory: expected stdio, got %s", mem.Transport)
	}
	if mem.Package != "@cline/mcp-server-memory" {
		t.Errorf("memory: expected @cline/mcp-server-memory, got %s", mem.Package)
	}
	if mem.Tool != "cline-roo" {
		t.Errorf("memory: expected tool=cline-roo, got %s", mem.Tool)
	}

	browser := findServer(t, servers, "browser")
	if browser.Transport != "http" {
		t.Errorf("browser: expected http, got %s", browser.Transport)
	}
}

func TestParseZedCamelCase(t *testing.T) {
	servers, err := parseZedSettings(mustRead(t, "zed_camel.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}

	s := findServer(t, servers, "linter")
	if s.Transport != "stdio" {
		t.Errorf("linter: expected stdio, got %s", s.Transport)
	}
	if s.Package != "@zed/mcp-server-linter" {
		t.Errorf("linter: expected @zed/mcp-server-linter, got %s", s.Package)
	}
	if s.Tool != "zed" {
		t.Errorf("linter: expected tool=zed, got %s", s.Tool)
	}
}

func TestParseZedUnderscore(t *testing.T) {
	servers, err := parseZedSettings(mustRead(t, "zed_underscore.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}

	s := findServer(t, servers, "formatter")
	if s.Transport != "stdio" {
		t.Errorf("formatter: expected stdio, got %s", s.Transport)
	}
	if s.Package != "mcp-formatter" {
		t.Errorf("formatter: expected mcp-formatter, got %s", s.Package)
	}
	if s.Tool != "zed" {
		t.Errorf("formatter: expected tool=zed, got %s", s.Tool)
	}
}

func TestParseZedEmpty(t *testing.T) {
	servers, err := parseZedSettings(mustRead(t, "zed_empty.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 0 {
		t.Errorf("expected 0 servers, got %d", len(servers))
	}
}

func TestRegistryIncludesAllTools(t *testing.T) {
	initRegistry()
	tools := Registry()

	names := set.New[string](0)
	for _, tp := range tools {
		names.Insert(tp.Name)
	}

	expected := []string{
		"claude", "cursor", "windsurf", "vscode", "continue", "opencode",
		"copilot-cli", "claude-code", "codex", "gemini", "cline-roo", "zed",
	}
	for _, name := range expected {
		if !names.Contains(name) {
			t.Errorf("expected tool %q in registry, but not found", name)
		}
	}
	if len(tools) != len(expected) {
		t.Errorf("expected %d tools in registry, got %d", len(expected), len(tools))
	}
}

func TestExtractPackage(t *testing.T) {
	tests := []struct {
		command  string
		args     []string
		expected string
	}{
		{"npx", []string{"-y", "@scope/pkg"}, "@scope/pkg"},
		{"uvx", []string{"mcp-server"}, "mcp-server"},
		{"go", []string{"run", "./cmd/server"}, "./cmd/server"},
		{"pipx", []string{"run", "mypackage"}, "mypackage"},
		{"prospect", nil, "prospect"},
		{"/usr/local/bin/my-server", nil, ""},
		{"npx", []string{"-y"}, ""},
	}

	for _, tt := range tests {
		got := extractPackage(tt.command, tt.args)
		if got != tt.expected {
			t.Errorf("extractPackage(%q, %v) = %q, want %q",
				tt.command, tt.args, got, tt.expected)
		}
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	return data
}

func findServer(t *testing.T, servers []ServerEntry, name string) *ServerEntry {
	t.Helper()
	for i := range servers {
		if servers[i].Name == name {
			return &servers[i]
		}
	}
	t.Fatalf("server %q not found in results", name)
	return nil
}
