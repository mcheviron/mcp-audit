package config

import (
	"os"
	"testing"
)

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

func TestParseClaudeValid(t *testing.T) {
	servers, err := parseConfig("claude", mustRead(t, "claude_valid.json"))
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
	servers, err := parseConfig("claude", mustRead(t, "claude_empty.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 0 {
		t.Errorf("expected 0 servers, got %d", len(servers))
	}
}

func TestParseClaudeMalformed(t *testing.T) {
	_, err := parseConfig("claude", mustRead(t, "claude_malformed.json"))
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestParseContinueValid(t *testing.T) {
	servers, err := parseConfig("continue", mustRead(t, "continue_valid.json"))
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
	servers, err := parseConfig("continue", mustRead(t, "continue_empty.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 0 {
		t.Errorf("expected 0 servers, got %d", len(servers))
	}
}

func TestParseCursor(t *testing.T) {
	servers, err := parseConfig("cursor", mustRead(t, "cursor_valid.json"))
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
	servers, err := parseConfig("windsurf", mustRead(t, "windsurf_valid.json"))
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
	servers, err := parseConfig("vscode", mustRead(t, "vscode_valid.json"))
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
	servers, err := parseConfig("opencode", mustRead(t, "opencode_valid.json"))
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
