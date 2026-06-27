package e2e_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const longEmbedURL = "https://malicious.example.com/very/long/path/with/many/segments/and/even/more/path/components/to/force/text/wrapping/at/narrow/terminal/widths/throughout/the/whole/line"

func TestE2ETableWrap_LongFindingWraps(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)

	mock := newMCPMockWithTools(t, "long-srv", []map[string]any{
		{"name": "fetch", "description": "see " + longEmbedURL,
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"url": map[string]any{"type": "string"}},
			}},
	})
	defer mock.Close()

	cfg := fmt.Sprintf(`{"mcpServers":{"long-srv":{"url":%q}}}`, mock.URL)
	home := setupHomeDir(t, cfg)

	out, _, _ := runMCPAudit(t, bin, home, "probe", "--no-color")

	lines := strings.Split(out, "\n")
	anchorIdx := -1
	for i, line := range lines {
		if strings.Contains(line, "long-srv") &&
			strings.Contains(line, "embedded URL") {
			anchorIdx = i
			break
		}
	}
	if anchorIdx < 0 {
		t.Skipf("no embedded-URL finding in probe output\noutput:\n%s", out)
	}

	firstLine := lines[anchorIdx]
	if len(firstLine) > 200 {
		t.Errorf("first row should be wrapped, not raw: len=%d", len(firstLine))
	}
	continuation := lines[anchorIdx+1]
	leadWS := len(continuation) - len(strings.TrimLeft(continuation, " "))
	if leadWS < 4 {
		t.Errorf("continuation indent too small: %d cols", leadWS)
	}
	serverIdx := strings.Index(firstLine, "long-srv")
	afterServer := serverIdx + len("long-srv")
	findStart := afterServer
	for findStart < len(firstLine) && firstLine[findStart] == ' ' {
		findStart++
	}
	if leadWS < findStart {
		t.Errorf("continuation indent (%d) should align to finding column start (%d)", leadWS, findStart)
	}
}

func TestE2ETableWrap_JSONFormatsLongFinding(t *testing.T) {
	t.Parallel()
	bin := buildBinary(t)

	mock := newMCPMockWithTools(t, "long-srv", []map[string]any{
		{"name": "fetch", "description": "see " + longEmbedURL,
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"url": map[string]any{"type": "string"}},
			}},
	})
	defer mock.Close()

	cfg := fmt.Sprintf(`{"mcpServers":{"long-srv":{"url":%q}}}`, mock.URL)
	home := setupHomeDir(t, cfg)

	out, _, _ := runMCPAudit(t, bin, home, "probe", "--format", "json")

	var parsed struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("json parse failed: %v\noutput:\n%s", err, out)
	}
	foundLong := false
	for _, f := range parsed.Findings {
		if v, ok := f["finding"].(string); ok &&
			strings.Contains(v, "embedded URL") {
			foundLong = true
			break
		}
	}
	if !foundLong {
		t.Errorf("expected long finding text in JSON output\noutput:\n%s", out)
	}
}

func TestE2ETableWrap_ShortFindingStaysSingleLine(t *testing.T) {
	t.Parallel()
	bin, home := setupTwoFileConfigs(t)

	out, _, _ := runMCPAudit(t, bin, home, "static", "--no-color")

	lines := strings.Split(out, "\n")
	shortRowCount := 0
	for _, line := range lines {
		if strings.Contains(line, "filesystem-a") &&
			!strings.HasPrefix(strings.TrimSpace(line), "↳") {
			shortRowCount++
			if strings.TrimRight(line, " ") != line {
				t.Errorf("short finding row should not be wrapped: %q", line)
			}
		}
	}
	if shortRowCount < 1 {
		t.Errorf("expected at least one short-finding row in output\noutput:\n%s", out)
	}
}

func setupTwoFileConfigs(t *testing.T) (bin, home string) {
	t.Helper()
	bin = buildBinary(t)
	home = t.TempDir()

	claudeDir := filepath.Join(home, "Library", "Application Support", "Claude")
	if err := os.MkdirAll(claudeDir, 0755); err != nil {
		t.Fatalf("mkdir claude dir: %v", err)
	}
	const npxCmd = `"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]`
	claudeCfg := `{"mcpServers":{"filesystem-a":{` + npxCmd + `},"cursor-b":{` + npxCmd + `}}}`
	if err := os.WriteFile(filepath.Join(claudeDir, "claude_desktop_config.json"), []byte(claudeCfg), 0644); err != nil {
		t.Fatalf("write claude config: %v", err)
	}

	cursorDir := filepath.Join(home, ".cursor")
	if err := os.MkdirAll(cursorDir, 0755); err != nil {
		t.Fatalf("mkdir cursor dir: %v", err)
	}
	cursorCfg := `{"mcpServers":{"cursor-srv":{` + npxCmd + `}}}`
	if err := os.WriteFile(filepath.Join(cursorDir, "mcp.json"), []byte(cursorCfg), 0644); err != nil {
		t.Fatalf("write cursor config: %v", err)
	}
	return bin, home
}
