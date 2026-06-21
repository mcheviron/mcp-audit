package config

import (
	"os"
	"reflect"
	"testing"
)

func TestParseCodexTomlStdio(t *testing.T) {
	data := []byte(`
[mcp_servers.my-server]
command = "npx"
args = ["-y", "@scope/pkg"]
`)
	servers, err := parseCodexToml(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
	s := servers[0]
	if s.Name != "my-server" {
		t.Errorf("expected Name=my-server, got %q", s.Name)
	}
	if s.Transport != "stdio" {
		t.Errorf("expected Transport=stdio, got %q", s.Transport)
	}
	if s.Command != "npx" {
		t.Errorf("expected Command=npx, got %q", s.Command)
	}
	if s.Package != "@scope/pkg" {
		t.Errorf("expected Package=@scope/pkg, got %q", s.Package)
	}
	if s.Tool != "codex" {
		t.Errorf("expected Tool=codex, got %q", s.Tool)
	}
}

func TestParseCodexTomlHTTP(t *testing.T) {
	data := []byte(`
[mcp_servers.remote]
url = "https://example.com/mcp"
`)
	servers, err := parseCodexToml(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
	s := servers[0]
	if s.Name != "remote" {
		t.Errorf("expected Name=remote, got %q", s.Name)
	}
	if s.Transport != "sse" {
		t.Errorf("expected Transport=sse, got %q", s.Transport)
	}
	if s.URL != "https://example.com/mcp" {
		t.Errorf("expected URL=https://example.com/mcp, got %q", s.URL)
	}
}

func TestParseCodexTomlBearerToken(t *testing.T) {
	os.Setenv("TEST_API_TOKEN", "secret123")
	defer os.Unsetenv("TEST_API_TOKEN")

	data := []byte(`
[mcp_servers.auth-server]
command = "node"
args = ["server.js"]
bearer_token_env_var = "TEST_API_TOKEN"
`)
	servers, err := parseCodexToml(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
	if servers[0].AuthToken != "secret123" {
		t.Errorf("expected AuthToken=secret123, got %q", servers[0].AuthToken)
	}
}

func TestParseCodexTomlHeaders(t *testing.T) {
	data := []byte(`
[mcp_servers.header-server]
command = "echo"
http_headers = { X-Custom = "value1", Authorization = "Bearer tok" }
`)
	servers, err := parseCodexToml(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
	if servers[0].Headers["X-Custom"] != "value1" {
		t.Errorf("expected X-Custom=value1, got %q", servers[0].Headers["X-Custom"])
	}
	if servers[0].AuthHeaders["Authorization"] != "Bearer tok" {
		t.Errorf("expected Authorization=Bearer tok, got %q", servers[0].AuthHeaders["Authorization"])
	}
}

func TestParseCodexTomlEnv(t *testing.T) {
	data := []byte(`
[mcp_servers.env-server]
command = "python"
env = { NODE_ENV = "production", PORT = "3000" }
`)
	servers, err := parseCodexToml(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
	if servers[0].Env["NODE_ENV"] != "production" {
		t.Errorf("expected NODE_ENV=production, got %q", servers[0].Env["NODE_ENV"])
	}
	if servers[0].Env["PORT"] != "3000" {
		t.Errorf("expected PORT=3000, got %q", servers[0].Env["PORT"])
	}
}

func TestParseCodexTomlMalformed(t *testing.T) {
	data := []byte(`this is not valid toml {{{`)
	_, err := parseCodexToml(data)
	if err == nil {
		t.Fatal("expected error for malformed TOML")
	}
}

func TestParseCodexTomlEmpty(t *testing.T) {
	data := []byte(``)
	servers, err := parseCodexToml(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 0 {
		t.Errorf("expected 0 servers, got %d", len(servers))
	}
}

func TestParseCodexTomlAllFields(t *testing.T) {
	os.Setenv("MY_TOKEN", "tok123")
	defer os.Unsetenv("MY_TOKEN")

	data := []byte(`
[mcp_servers.full]
command = "my-binary"
args = ["serve", "--port", "8080"]
url = "https://api.example.com"
bearer_token_env_var = "MY_TOKEN"
http_headers = { X-API-Key = "key123" }
env = { DEBUG = "1" }
`)
	servers, err := parseCodexToml(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
	s := servers[0]
	if s.Name != "full" {
		t.Errorf("expected Name=full, got %q", s.Name)
	}
	if s.Command != "my-binary" {
		t.Errorf("expected Command=my-binary, got %q", s.Command)
	}
	if !reflect.DeepEqual(s.Args, []string{"serve", "--port", "8080"}) {
		t.Errorf("unexpected Args: %v", s.Args)
	}
	if s.URL != "https://api.example.com" {
		t.Errorf("expected URL=https://api.example.com, got %q", s.URL)
	}
	if s.AuthToken != "tok123" {
		t.Errorf("expected AuthToken=tok123, got %q", s.AuthToken)
	}
	if s.Headers["X-API-Key"] != "key123" {
		t.Errorf("expected X-API-Key=key123, got %q", s.Headers["X-API-Key"])
	}
	if s.Env["DEBUG"] != "1" {
		t.Errorf("expected DEBUG=1, got %q", s.Env["DEBUG"])
	}
}

func TestResolveParserJSON(t *testing.T) {
	fn := resolveParser("json", nil)
	if fn == nil {
		t.Fatal("expected non-nil parser for json format")
	}
}

func TestResolveParserTOML(t *testing.T) {
	fn := resolveParser("toml", nil)
	if fn == nil {
		t.Fatal("expected non-nil parser for toml format")
	}
}

func TestResolveParserTOMLCaseInsensitive(t *testing.T) {
	fn := resolveParser("TOML", nil)
	if fn == nil {
		t.Fatal("expected non-nil parser for TOML format (case insensitive)")
	}
}

func TestResolveParserExplicitWins(t *testing.T) {
	custom := func(data []byte) ([]ServerEntry, error) {
		return nil, nil
	}
	fn := resolveParser("json", custom)
	if fn == nil {
		t.Fatal("expected non-nil parser")
	}
}
