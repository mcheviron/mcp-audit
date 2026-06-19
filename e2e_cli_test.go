package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestE2EWatchSubcommandExists(t *testing.T) {
	bin := buildBinary(t)

	cmd := exec.Command(bin, "watch", "-watch-interval=5")
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start watch: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		cmd.Process.Kill()
	}
}

func TestE2EWatchInvalidInterval(t *testing.T) {
	bin := buildBinary(t)

	cmd := exec.Command(bin, "watch", "-watch-interval=1")
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err == nil {
		t.Fatal("expected error for watch-interval less than 5")
	}

	stderrStr := stderr.String()
	if !strings.Contains(stderrStr, "at least 5") {
		t.Errorf("expected 'at least 5' error, got: %s", stderrStr)
	}
}

func TestE2EProxyMissingTarget(t *testing.T) {
	bin := buildBinary(t)

	cmd := exec.Command(bin, "proxy")
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err == nil {
		t.Fatal("expected error for missing --target")
	}

	if !strings.Contains(stderr.String(), "target") {
		t.Errorf("expected 'target' in error, got: %s", stderr.String())
	}
}

func TestE2EProxySubcommandStarts(t *testing.T) {
	bin := buildBinary(t)

	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"name":"test","version":"1.0"},"protocolVersion":"2024-11-05","capabilities":{}}}`))
	}))
	defer targetServer.Close()

	cmd := exec.Command(bin, "proxy", "--target", targetServer.URL, "--listen", "127.0.0.1:0")
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start proxy: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		cmd.Process.Kill()
	}
}

func TestE2EHelpShowsWatchProxy(t *testing.T) {
	bin := buildBinary(t)

	cmd := exec.Command(bin, "help")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("help failed: %v", err)
	}

	outStr := string(out)
	if !strings.Contains(outStr, "watch") {
		t.Error("help output missing 'watch' subcommand")
	}
	if !strings.Contains(outStr, "proxy") {
		t.Error("help output missing 'proxy' subcommand")
	}
}

func TestE2ENoArgsShowsHelp(t *testing.T) {
	bin := buildBinary(t)

	cmd := exec.Command(bin)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("no-args failed: %v", err)
	}
	if !strings.Contains(string(out), "Usage") {
		t.Error("no-args output missing 'Usage'")
	}
}

func TestE2EInvalidSubcommand(t *testing.T) {
	bin := buildBinary(t)

	cmd := exec.Command(bin, "nonexistent")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err == nil {
		t.Fatal("expected error for invalid subcommand")
	}

	if !strings.Contains(stderr.String(), "unknown command") {
		t.Errorf("expected 'unknown command', got: %s", stderr.String())
	}
}

func TestE2EStaticJSONOutput(t *testing.T) {
	bin := buildBinary(t)

	claudeCfg := `{
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
			}
		}
	}`

	home := setupHomeDir(t, claudeCfg)
	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json", "--no-color")
	if code != 0 {
		t.Errorf("expected exit 0 for json output, got %d\noutput:\n%s", code, out)
	}

	var data struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &data); err != nil {
		t.Fatalf("invalid JSON output: %v\noutput:\n%s", err, out)
	}
	if len(data.Findings) == 0 {
		t.Error("expected non-empty findings array")
	}
}
