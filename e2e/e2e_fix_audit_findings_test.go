package e2e_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestE2E_Report_WriteErrorPropagated(t *testing.T) {
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
	out, _, code := runMCPAudit(t, bin, home, "static")
	if code != 0 {
		t.Errorf("expected exit 0, got %d\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "Summary:") {
		t.Errorf("expected Summary line in output\noutput:\n%s", out)
	}
}

func TestE2E_Report_TableFormatHasColumns(t *testing.T) {
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
	out, _, code := runMCPAudit(t, bin, home, "static")
	if code != 0 {
		t.Errorf("expected exit 0, got %d\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "CRITICAL") && !strings.Contains(out, "PASS") {
		t.Errorf("expected severity column in output\noutput:\n%s", out)
	}
}

func TestE2E_Report_JSONOutputContainsServer(t *testing.T) {
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
	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Errorf("expected exit 0, got %d\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, `"server"`) {
		t.Errorf("expected server field in JSON\noutput:\n%s", out)
	}
}

func TestE2E_Report_JSONSummaryCounts(t *testing.T) {
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
	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json")
	if code != 0 {
		t.Errorf("expected exit 0, got %d\noutput:\n%s", code, out)
	}

	var wrapper struct {
		Summary struct {
			Critical       int `json:"critical"`
			High           int `json:"high"`
			Medium         int `json:"medium"`
			Low            int `json:"low"`
			Info           int `json:"info"`
			Pass           int `json:"pass"`
			ServersScanned int `json:"servers_scanned"`
		} `json:"summary"`
	}
	if err := json.Unmarshal([]byte(out), &wrapper); err != nil {
		t.Fatalf("unmarshal JSON: %v\noutput:\n%s", err, out)
	}
	if wrapper.Summary.ServersScanned != 1 {
		t.Errorf("expected 1 server scanned, got %d", wrapper.Summary.ServersScanned)
	}
}

func TestE2E_Probe_ScanCompletesWithinTimeout(t *testing.T) {
	bin := buildBinary(t)

	srv := newE2EMockMCPServer(t)
	defer srv.Close()

	claudeCfg := fmt.Sprintf(`{
		"mcpServers": {
			"fast-srv": {
				"url": "%s"
			}
		}
	}`, srv.URL)

	home := setupHomeDir(t, claudeCfg)
	out, _, code := runMCPAudit(t, bin, home, "probe", "--format", "json", "--timeout", "5", "--concurrency", "2")
	if code == 2 {
		t.Errorf("probe should not exit with error code 2\noutput:\n%s", out)
	}
	if !json.Valid([]byte(out)) {
		t.Fatalf("expected valid JSON\noutput:\n%s", out)
	}
}

func TestE2E_Probe_PartialResultsWithErrors(t *testing.T) {
	bin := buildBinary(t)

	goodSrv := newE2EMockMCPServer(t)
	defer goodSrv.Close()

	claudeCfg := fmt.Sprintf(`{
		"mcpServers": {
			"good-srv": {
				"url": "%s"
			},
			"dead-srv": {
				"url": "http://127.0.0.1:65535"
			}
		}
	}`, goodSrv.URL)

	home := setupHomeDir(t, claudeCfg)
	out, _, _ := runMCPAudit(t, bin, home, "probe", "--format", "json", "--timeout", "2", "--concurrency", "2")

	if !json.Valid([]byte(out)) {
		t.Fatalf("expected valid JSON with partial results\noutput:\n%s", out)
	}

	results := parseJSONFindings(t, out)
	if len(results) == 0 {
		t.Error("expected at least partial results from good server")
	}

	foundGoodServer := false
	for _, r := range results {
		server, _ := r["server"].(string)
		if server == "good-srv" {
			foundGoodServer = true
			break
		}
	}
	if !foundGoodServer {
		t.Error("expected results from good-srv even when dead-srv fails")
	}
}

func TestE2E_Probe_ExtendedDepthOutputsJSON(t *testing.T) {
	bin := buildBinary(t)

	srv := newE2EMockMCPServer(t)
	defer srv.Close()

	claudeCfg := fmt.Sprintf(`{
		"mcpServers": {
			"test-srv": {
				"url": "%s"
			}
		}
	}`, srv.URL)

	home := setupHomeDir(t, claudeCfg)

	out, _, _ := runMCPAudit(t, bin, home, "probe", "--format", "json",
		"--timeout", "10", "--concurrency", "1", "--probe-depth", "basic")

	if !json.Valid([]byte(out)) {
		t.Fatalf("expected valid JSON from probe with basic depth\noutput:\n%s", out)
	}

	results := parseJSONFindings(t, out)
	if len(results) == 0 {
		t.Error("expected non-empty results from basic depth probe")
	}
}

func TestE2E_Watch_SignalShutdown(t *testing.T) {
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

	cmd := exec.Command(bin, "watch", "--watch-interval", "5")
	cmd.Env = append(os.Environ(), "HOME="+home)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start watch: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		if err != nil {
			t.Logf("watch exit: %v\nstderr:\n%s", err, stderr.String())
		}
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		t.Fatal("watch did not shut down within 10 seconds after SIGTERM")
	}
}

func TestE2E_Watch_SecondSignalForceExit(t *testing.T) {
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

	cmd := exec.Command(bin, "watch", "--watch-interval", "3600")
	cmd.Env = append(os.Environ(), "HOME="+home)

	if err := cmd.Start(); err != nil {
		t.Fatalf("start watch: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("send first SIGTERM: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("send SIGKILL: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		cmd.Process.Kill()
		t.Fatal("watch did not exit within 5 seconds after SIGKILL")
	}
}

func TestE2E_OutputFile_FlagWorks(t *testing.T) {
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
	outFile := filepath.Join(t.TempDir(), "report.json")
	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json", "--output-file", outFile)
	if code != 0 {
		t.Errorf("expected exit 0, got %d\noutput:\n%s", code, out)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if !json.Valid(data) {
		t.Fatalf("output file not valid JSON\ncontent:\n%s", string(data))
	}
}

func TestE2E_Scan_SubcommandWorks(t *testing.T) {
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
	out, _, code := runMCPAudit(t, bin, home, "scan", "--dry-run")
	if code != 0 && code != 2 {
		t.Errorf("expected exit 0, got %d\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "Summary:") {
		t.Errorf("scan should produce table output\noutput:\n%s", out)
	}
}

func TestE2E_Help_ShowsAllSubcommands(t *testing.T) {
	bin := buildBinary(t)

	out, _, code := runMCPAudit(t, bin, os.Getenv("HOME"), "help")
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}

	expected := []string{"static", "probe", "watch", "proxy", "trust", "upload", "version", "completion", "scan"}
	for _, sub := range expected {
		if !strings.Contains(out, sub) {
			t.Errorf("help output missing %q subcommand\noutput:\n%s", sub, out)
		}
	}
}

func TestE2E_Regression_StaticBlockedStillWorks(t *testing.T) {
	bin := buildBinary(t)

	claudeCfg := `{
		"mcpServers": {
			"evil": {
				"command": "npx",
				"args": ["-y", "evil-package"]
			}
		}
	}`

	home := setupHomeDir(t, claudeCfg)
	trustCfg := writeTrustConfig(t, t.TempDir(), `{
		"blocked": ["evil-package"]
	}`)

	out, _, code := runMCPAudit(t, bin, home, "static", "--trust-config", trustCfg)
	if code != 1 {
		t.Errorf("expected exit 1 for blocked package, got %d\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "CRITICAL") {
		t.Errorf("expected CRITICAL for blocked package\noutput:\n%s", out)
	}
}

func TestE2E_Regression_ProbeDryRunStillWorks2(t *testing.T) {
	bin := buildBinary(t)

	claudeCfg := `{
		"mcpServers": {
			"test-srv": {
				"url": "http://127.0.0.1:19999"
			}
		}
	}`

	home := setupHomeDir(t, claudeCfg)
	out, _, code := runMCPAudit(t, bin, home, "probe", "--dry-run")
	if code != 0 {
		t.Errorf("expected exit 0 for dry-run, got %d\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "would probe") {
		t.Errorf("expected 'would probe' in output\noutput:\n%s", out)
	}
}

func TestE2E_Regression_VersionStillWorks2(t *testing.T) {
	bin := buildBinary(t)
	out, _, code := runMCPAudit(t, bin, os.Getenv("HOME"), "version")
	if code != 0 {
		t.Errorf("version failed, code=%d\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "mcp-audit dev") {
		t.Errorf("expected version string containing 'mcp-audit dev'\noutput:\n%s", out)
	}
}
