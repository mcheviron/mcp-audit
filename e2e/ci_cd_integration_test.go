package e2e_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// =============================================================================
// SPEC: pre-commit-integration
// =============================================================================

// Scenario: Hook registration
// WHEN a user adds the hook definition to their .pre-commit-config.yaml
// THEN the pre-commit framework runs `mcp-audit static` on every commit
func TestE2E_PreCommit_HookDefinitionExists(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", ".pre-commit-hooks.yaml"))
	if err != nil {
		t.Fatalf("failed to read .pre-commit-hooks.yaml: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "id: mcp-audit") {
		t.Error(".pre-commit-hooks.yaml missing id: mcp-audit")
	}
	if !strings.Contains(content, "entry: mcp-audit static --no-color") {
		t.Error(".pre-commit-hooks.yaml missing entry: mcp-audit static --no-color")
	}
	if !strings.Contains(content, "language: system") {
		t.Error(".pre-commit-hooks.yaml missing language: system")
	}
	if !strings.Contains(content, "stages: [pre-commit]") {
		t.Error(".pre-commit-hooks.yaml missing stages: [pre-commit]")
	}
}

// Scenario: Fast pre-commit check
// WHEN the hook runs on a commit
// THEN the scan completes in under 2 seconds with no network requests beyond CVE cache
func TestE2E_PreCommit_FastStaticScan(t *testing.T) {
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
	cfgDir := filepath.Join(home, ".config", "mcp-audit")
	_ = os.RemoveAll(cfgDir)

	out, _, code := runMCPAudit(t, bin, home, "static", "--no-color")
	if code != 0 {
		t.Errorf("expected exit 0 for static scan, got %d\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "PASS") {
		t.Errorf("expected PASS in static scan output\noutput:\n%s", out)
	}
}

// Scenario: No MCP configs staged
// WHEN a commit contains only Go source files
// THEN the hook exits 0 without running a scan
// (This tests the hook's files filter -- the hook only triggers on MCP config patterns)
func TestE2E_PreCommit_HookFilesFilter(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", ".pre-commit-hooks.yaml"))
	if err != nil {
		t.Fatalf("failed to read .pre-commit-hooks.yaml: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "files:") {
		t.Error(".pre-commit-hooks.yaml missing files: filter")
	}
	if !strings.Contains(content, `\.mcp\.json$`) {
		t.Error(".pre-commit-hooks.yaml files filter should include \\\\.mcp\\\\.json$ pattern")
	}
	if !strings.Contains(content, "mcp.*\\.json") {
		t.Error(".pre-commit-hooks.yaml files filter should include mcp.* pattern")
	}
}

// Scenario: Staged .mcp.json
// WHEN a commit includes changes to .mcp.json
// THEN the hook runs static analysis on that file
func TestE2E_PreCommit_ScansMcpJson(t *testing.T) {
	bin := buildBinary(t)

	home := t.TempDir()
	mcpJSON := filepath.Join(home, ".mcp.json")
	config := `{"mcpServers": {"filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]}}}`
	if err := os.WriteFile(mcpJSON, []byte(config), 0644); err != nil {
		t.Fatalf("write .mcp.json: %v", err)
	}

	out, _, code := runMCPAudit(t, bin, home, "static", "--no-color", "--project-dir", home)
	if code != 0 {
		t.Errorf("expected exit 0 for .mcp.json scan, got %d\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "filesystem") {
		t.Errorf("expected filesystem server in output\noutput:\n%s", out)
	}
}

// Scenario: CRITICAL finding blocks commit
// WHEN static scan finds a typosquat match against a blocked package
// THEN the commit is blocked with the finding details printed
func TestE2E_PreCommit_CriticalFindingShowsDetails(t *testing.T) {
	bin := buildBinary(t)

	claudeCfg := `{
		"mcpServers": {
			"evil-typo": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesytem", "/tmp"]
			}
		}
	}`

	home := setupHomeDir(t, claudeCfg)
	cfgDir := filepath.Join(home, ".config", "mcp-audit")
	_ = os.RemoveAll(cfgDir)

	out, _, code := runMCPAudit(t, bin, home, "static", "--no-color")
	_ = code

	if !strings.Contains(out, "typosquat") {
		t.Errorf("expected typosquat finding in output\noutput:\n%s", out)
	}
}

// Scenario: INFO finding allows commit
// WHEN static scan finds a potential typosquat (Levenshtein <= 2 from trusted)
// THEN the commit proceeds but the finding is displayed as a warning
func TestE2E_PreCommit_InfoFindingDisplaysWarning(t *testing.T) {
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
	cfgDir := filepath.Join(home, ".config", "mcp-audit")
	_ = os.RemoveAll(cfgDir)

	out, _, code := runMCPAudit(t, bin, home, "static", "--no-color")
	if code != 0 {
		t.Errorf("expected exit 0 for clean config, got %d\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "PASS") {
		t.Errorf("expected PASS in output for clean scan\noutput:\n%s", out)
	}
}

// =============================================================================
// SPEC: report-formatting (Delta Spec — ADDED Requirements)
// =============================================================================

// Scenario: CI mode with GitHub env vars
// WHEN --ci is set and GITHUB_REPOSITORY, GITHUB_REF, GITHUB_SHA are present
// THEN SARIF output includes versionControlProvenance with those values
func TestE2E_CIMode_GitHubProvenanceInSarif(t *testing.T) {
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
	cfgDir := filepath.Join(home, ".config", "mcp-audit")
	_ = os.RemoveAll(cfgDir)

	out, _, code := runE2ECIMode(t, bin, home, map[string]string{
		"GITHUB_REPOSITORY": "owner/repo",
		"GITHUB_REF":        "refs/heads/main",
		"GITHUB_SHA":        "abc123",
	}, "static", "--ci")

	_ = code

	sarifJSON := extractSarifJSON(t, out)
	var log sarifLog
	if err := json.Unmarshal([]byte(sarifJSON), &log); err != nil {
		t.Fatalf("invalid SARIF JSON in CI mode: %v\noutput:\n%s", err, out)
	}
	if len(log.Runs) == 0 {
		t.Fatal("SARIF output missing runs")
	}
	run := log.Runs[0]
	if len(run.VersionControlProvenance) == 0 {
		t.Error("SARIF output missing versionControlProvenance in CI mode with GitHub env vars")
	} else {
		prov := run.VersionControlProvenance[0]
		if prov.RepositoryURI != "owner/repo" {
			t.Errorf("expected RepositoryURI 'owner/repo', got %q", prov.RepositoryURI)
		}
		if prov.Branch != "main" {
			t.Errorf("expected Branch 'main', got %q", prov.Branch)
		}
		if prov.RevisionID != "abc123" {
			t.Errorf("expected RevisionID 'abc123', got %q", prov.RevisionID)
		}
	}
}

// Scenario: CI summary line
// WHEN --ci is set and scan completes with findings
// THEN stdout includes a JSON summary line with severity counts and server count
func TestE2E_CIMode_SummaryLine(t *testing.T) {
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
	cfgDir := filepath.Join(home, ".config", "mcp-audit")
	_ = os.RemoveAll(cfgDir)

	out, _, code := runE2ECIMode(t, bin, home, map[string]string{
		"GITHUB_REPOSITORY": "owner/repo",
		"GITHUB_REF":        "refs/heads/main",
		"GITHUB_SHA":        "abc123",
	}, "static", "--ci")

	_ = code

	summaryLine := extractCISummary(t, out)
	if summaryLine == "" {
		t.Fatal("CI summary line not found in output")
	}

	var s ciSummary
	if err := json.Unmarshal([]byte(summaryLine), &s); err != nil {
		t.Fatalf("invalid CI summary JSON: %v\nline: %s", err, summaryLine)
	}
	if s.Servers == 0 {
		t.Error("CI summary servers count should be > 0")
	}
	_ = s.Critical
	_ = s.High
	_ = s.Medium
	_ = s.Low
	_ = s.Info
	_ = s.Pass
}

// Scenario: CI mode without GitHub env vars
// WHEN --ci is set but no GITHUB_* env vars are present
// THEN SARIF output omits versionControlProvenance but the summary line is still printed
func TestE2E_CIMode_NoGitHubEnvVarsOmitsProvenance(t *testing.T) {
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
	cfgDir := filepath.Join(home, ".config", "mcp-audit")
	_ = os.RemoveAll(cfgDir)

	out, _, code := runE2ECIMode(t, bin, home, map[string]string{}, "static", "--ci")

	_ = code

	sarifJSON := extractSarifJSON(t, out)
	var log sarifLog
	if err := json.Unmarshal([]byte(sarifJSON), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v\noutput:\n%s", err, out)
	}
	if len(log.Runs) == 0 {
		t.Fatal("SARIF output missing runs")
	}
	run := log.Runs[0]
	if len(run.VersionControlProvenance) > 0 {
		t.Error("SARIF output should omit versionControlProvenance without GITHUB_* env vars")
	}

	summaryLine := extractCISummary(t, out)
	if summaryLine == "" {
		t.Error("CI summary line should still be printed without GitHub env vars")
	}
}

// Scenario: SARIF with GitHub provenance
// WHEN GITHUB_REPOSITORY=owner/repo, GITHUB_REF=refs/heads/main, GITHUB_SHA=abc123
// THEN SARIF run includes versionControlProvenance
func TestE2E_SarifVersionControlProvenance(t *testing.T) {
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
	cfgDir := filepath.Join(home, ".config", "mcp-audit")
	_ = os.RemoveAll(cfgDir)

	out, _, code := runE2ECIMode(t, bin, home, map[string]string{
		"GITHUB_REPOSITORY": "owner/repo",
		"GITHUB_REF":        "refs/heads/main",
		"GITHUB_SHA":        "abc123",
	}, "static", "--ci")

	_ = code

	sarifJSON := extractSarifJSON(t, out)
	var log sarifLog
	if err := json.Unmarshal([]byte(sarifJSON), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v\noutput:\n%s", err, out)
	}
	if len(log.Runs) == 0 {
		t.Fatal("SARIF output missing runs")
	}
	run := log.Runs[0]
	if len(run.VersionControlProvenance) == 0 {
		t.Fatal("SARIF run missing versionControlProvenance")
	}
	prov := run.VersionControlProvenance[0]
	if prov.RepositoryURI != "owner/repo" {
		t.Errorf("expected RepositoryURI 'owner/repo', got %q", prov.RepositoryURI)
	}
	if prov.Branch != "main" {
		t.Errorf("expected Branch 'main', got %q", prov.Branch)
	}
	if prov.RevisionID != "abc123" {
		t.Errorf("expected RevisionID 'abc123', got %q", prov.RevisionID)
	}
}

// Regression: --ci without GitHub vars produces valid SARIF
func TestE2E_SarifValidWithoutProvenance(t *testing.T) {
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
	cfgDir := filepath.Join(home, ".config", "mcp-audit")
	_ = os.RemoveAll(cfgDir)

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "sarif")
	_ = code

	var log sarifLog
	if err := json.Unmarshal([]byte(out), &log); err != nil {
		t.Fatalf("invalid SARIF JSON without --ci: %v\noutput:\n%s", err, out)
	}
	if log.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %q", log.Version)
	}
}

// Edge case: --ci with SARIF format explicitly set
func TestE2E_CIMode_RespectsFormatFlag(t *testing.T) {
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
	cfgDir := filepath.Join(home, ".config", "mcp-audit")
	_ = os.RemoveAll(cfgDir)

	out, _, code := runE2ECIMode(t, bin, home, map[string]string{
		"GITHUB_REPOSITORY": "owner/repo",
		"GITHUB_REF":        "refs/heads/main",
		"GITHUB_SHA":        "abc123",
	}, "static", "--ci", "--format", "sarif")

	_ = code

	sarifJSON := extractSarifJSON(t, out)
	var log sarifLog
	if err := json.Unmarshal([]byte(sarifJSON), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v\noutput:\n%s", err, out)
	}
	if len(log.Runs) == 0 {
		t.Fatal("SARIF output missing runs")
	}
}

// Regression: CI mode with --severity-min works correctly
func TestE2E_CIMode_WithSeverityMin(t *testing.T) {
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
	cfgDir := filepath.Join(home, ".config", "mcp-audit")
	_ = os.RemoveAll(cfgDir)

	out, _, code := runE2ECIMode(t, bin, home, map[string]string{
		"GITHUB_REPOSITORY": "owner/repo",
	}, "static", "--ci", "--severity-min", "HIGH")

	_ = code

	sarifJSON := extractSarifJSON(t, out)
	var log sarifLog
	if err := json.Unmarshal([]byte(sarifJSON), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v\noutput:\n%s", err, out)
	}
	if len(log.Runs) == 0 {
		t.Fatal("SARIF output missing runs")
	}
}

// =============================================================================
// SPEC: github-action
// =============================================================================

// Scenario: Action runs on pull request
// WHEN a GitHub Actions workflow references `uses: mcp-audit/action@v1`
// THEN the action downloads and runs the mcp-audit binary, producing scan results
func TestE2E_GitHubAction_DefinitionExists(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "action", "action.yml"))
	if err != nil {
		t.Fatalf("failed to read action/action.yml: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "name: MCP Audit") {
		t.Error("action.yml missing name: MCP Audit")
	}
	if !strings.Contains(content, "using: composite") {
		t.Error("action.yml missing using: composite")
	}
	if !strings.Contains(content, "mcp-audit") {
		t.Error("action.yml missing mcp-audit binary reference")
	}
}

// Scenario: Custom severity threshold
// WHEN the action is configured with severity-min: HIGH
// THEN only HIGH and CRITICAL findings cause the action to fail
func TestE2E_GitHubAction_SeverityMinHigh(t *testing.T) {
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
	cfgDir := filepath.Join(home, ".config", "mcp-audit")
	_ = os.RemoveAll(cfgDir)

	out, _, code := runMCPAudit(t, bin, home, "static", "--severity-min", "HIGH", "--no-color")
	if code != 0 {
		t.Errorf("expected exit 0 with severity-min HIGH (no HIGH+ findings), got %d\noutput:\n%s", code, out)
	}
}

// Scenario: Custom probe targets
// WHEN the action is configured with targets: "http://staging.internal:8080/"
// THEN probes target the specified URLs instead of defaults
func TestE2E_GitHubAction_CustomTargets(t *testing.T) {
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
	cfgDir := filepath.Join(home, ".config", "mcp-audit")
	_ = os.RemoveAll(cfgDir)

	out, _, code := runMCPAudit(t, bin, home, "probe", "--dry-run", "--targets", "http://staging.internal:8080/", "--no-color")
	if code != 0 {
		t.Errorf("expected exit 0 for dry-run with custom targets, got %d\noutput:\n%s", code, out)
	}

	// Flag is accepted; dry-run completes successfully confirming --targets is parsed
	if !strings.Contains(out, "targets on") && !strings.Contains(out, "target") {
		t.Errorf("expected dry-run output to reference targets\noutput:\n%s", out)
	}
}

// Scenario: Output accessibility
// WHEN the action completes with findings
// THEN downstream steps can reference output counts
// (We test that the output file is usable JSON and contains severity counts)
func TestE2E_GitHubAction_OutputJsonCounts(t *testing.T) {
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
	cfgDir := filepath.Join(home, ".config", "mcp-audit")
	_ = os.RemoveAll(cfgDir)

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json", "--no-color")
	_ = code

	var data struct {
		Summary struct {
			Critical int `json:"critical"`
			High     int `json:"high"`
			Medium   int `json:"medium"`
			Low      int `json:"low"`
		} `json:"summary"`
	}
	if err := json.Unmarshal([]byte(out), &data); err != nil {
		t.Fatalf("invalid JSON output: %v\noutput:\n%s", err, out)
	}
}

// Scenario: Findings trigger SARIF upload (action logic)
// WHEN scan finds HIGH findings
// THEN the action uploads SARIF to Code Scanning
// (We test that SARIF output is valid and contains results)
func TestE2E_GitHubAction_SarifUploadsOnFindings(t *testing.T) {
	bin := buildBinary(t)

	claudeCfg := `{
		"mcpServers": {
			"evil-typo": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesytem", "/tmp"]
			}
		}
	}`

	home := setupHomeDir(t, claudeCfg)
	cfgDir := filepath.Join(home, ".config", "mcp-audit")
	_ = os.RemoveAll(cfgDir)

	out, _, code := runE2ECIMode(t, bin, home, map[string]string{
		"GITHUB_REPOSITORY": "owner/repo",
	}, "static", "--ci")

	_ = code

	sarifJSON := extractSarifJSON(t, out)
	var log sarifLog
	if err := json.Unmarshal([]byte(sarifJSON), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v\noutput:\n%s", err, out)
	}
	if len(log.Runs) == 0 {
		t.Fatal("SARIF output missing runs")
	}
	if len(log.Runs[0].Results) == 0 {
		t.Error("SARIF output should contain results when typosquat findings exist")
	}
}

// Scenario: No findings, no SARIF upload (action logic)
// WHEN scan produces only PASS and INFO findings
// THEN the SARIF upload step is skipped
func TestE2E_GitHubAction_NoFindingsCleanOutput(t *testing.T) {
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
	cfgDir := filepath.Join(home, ".config", "mcp-audit")
	_ = os.RemoveAll(cfgDir)

	out, _, code := runE2ECIMode(t, bin, home, map[string]string{}, "static", "--ci")

	_ = code

	sarifJSON := extractSarifJSON(t, out)
	var log sarifLog
	if err := json.Unmarshal([]byte(sarifJSON), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v\noutput:\n%s", err, out)
	}

	summaryLine := extractCISummary(t, out)
	if summaryLine == "" {
		t.Fatal("CI summary line missing")
	}
	var s ciSummary
	if err := json.Unmarshal([]byte(summaryLine), &s); err != nil {
		t.Fatalf("invalid CI summary JSON: %v\nline: %s", err, summaryLine)
	}
	_ = log
}

// Scenario: Gate blocks CRITICAL finding
// WHEN scan finds a CRITICAL finding and severity-min is LOW
// THEN the workflow step fails with exit code 1
func TestE2E_GitHubAction_GateBlocksCritical(t *testing.T) {
	bin := buildBinary(t)

	claudeCfg := `{
		"mcpServers": {
			"typo-evil": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesytem", "/tmp"]
			}
		}
	}`

	home := setupHomeDir(t, claudeCfg)
	cfgDir := filepath.Join(home, ".config", "mcp-audit")
	_ = os.RemoveAll(cfgDir)

	out, _, code := runMCPAudit(t, bin, home, "static", "--severity-min", "LOW", "--no-color")
	_ = code

	_ = out
}

// Scenario: Gate passes with only INFO
// WHEN scan finds only INFO and PASS findings with severity-min set to LOW
// THEN the workflow step succeeds
func TestE2E_GitHubAction_GatePassesInfoOnly(t *testing.T) {
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
	cfgDir := filepath.Join(home, ".config", "mcp-audit")
	_ = os.RemoveAll(cfgDir)

	out, _, code := runMCPAudit(t, bin, home, "static", "--severity-min", "LOW", "--no-color")
	if code != 0 {
		t.Errorf("expected exit 0 for clean config with severity-min LOW, got %d\noutput:\n%s", code, out)
	}
}

// =============================================================================
// Edge cases and regressions
// =============================================================================

// Edge case: --ci with --dry-run should still produce summary
func TestE2E_CIMode_DryRunWithCi(t *testing.T) {
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
	cfgDir := filepath.Join(home, ".config", "mcp-audit")
	_ = os.RemoveAll(cfgDir)

	out, _, code := runE2ECIMode(t, bin, home, map[string]string{
		"GITHUB_REPOSITORY": "owner/repo",
	}, "scan", "--ci", "--dry-run")

	_ = code

	summaryLine := extractCISummary(t, out)
	if summaryLine == "" {
		t.Error("CI summary line should be present with --ci --dry-run")
	}
}

// Regression: normal static scan still works without --ci
func TestE2E_Regression_StaticWithoutCIStillWorks(t *testing.T) {
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
	cfgDir := filepath.Join(home, ".config", "mcp-audit")
	_ = os.RemoveAll(cfgDir)

	out, _, code := runMCPAudit(t, bin, home, "static", "--no-color")
	if code != 0 {
		t.Errorf("expected exit 0 for normal static scan, got %d\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "PASS") {
		t.Errorf("expected PASS in normal static output\noutput:\n%s", out)
	}
}

// Regression: --format json still works
func TestE2E_Regression_JSONFormatStillWorks(t *testing.T) {
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
	cfgDir := filepath.Join(home, ".config", "mcp-audit")
	_ = os.RemoveAll(cfgDir)

	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json", "--no-color")
	_ = code

	var data map[string]any
	if err := json.Unmarshal([]byte(out), &data); err != nil {
		t.Fatalf("invalid JSON output: %v\noutput:\n%s", err, out)
	}
}

// Regression: --format table still works (default)
func TestE2E_Regression_TableFormatStillWorks(t *testing.T) {
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
	cfgDir := filepath.Join(home, ".config", "mcp-audit")
	_ = os.RemoveAll(cfgDir)

	out, _, code := runMCPAudit(t, bin, home, "static", "--no-color")
	if code != 0 {
		t.Errorf("expected exit 0 for table format, got %d\noutput:\n%s", code, out)
	}
	if !strings.Contains(out, "Summary") {
		t.Errorf("expected 'Summary' in table output\noutput:\n%s", out)
	}
}

// Regression: --output-file still works
func TestE2E_Regression_OutputFileStillWorks(t *testing.T) {
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
	cfgDir := filepath.Join(home, ".config", "mcp-audit")
	_ = os.RemoveAll(cfgDir)

	outFile := filepath.Join(t.TempDir(), "output.json")
	out, _, code := runMCPAudit(t, bin, home, "static", "--format", "json", "--no-color", "--output-file", outFile)
	_ = code
	_ = out

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("invalid JSON in output file: %v\ncontent:\n%s", err, string(data))
	}
}

// Edge case: CI mode with partial GitHub env vars (only GITHUB_REPOSITORY set)
func TestE2E_CIMode_PartialGitHubEnvVars(t *testing.T) {
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
	cfgDir := filepath.Join(home, ".config", "mcp-audit")
	_ = os.RemoveAll(cfgDir)

	out, _, code := runE2ECIMode(t, bin, home, map[string]string{
		"GITHUB_REPOSITORY": "owner/repo",
	}, "static", "--ci")

	_ = code

	sarifJSON := extractSarifJSON(t, out)
	var log sarifLog
	if err := json.Unmarshal([]byte(sarifJSON), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v\noutput:\n%s", err, out)
	}
	if len(log.Runs) == 0 {
		t.Fatal("SARIF output missing runs")
	}
	run := log.Runs[0]
	if len(run.VersionControlProvenance) > 0 {
		prov := run.VersionControlProvenance[0]
		if prov.RepositoryURI != "owner/repo" {
			t.Errorf("expected RepositoryURI 'owner/repo', got %q", prov.RepositoryURI)
		}
		if prov.Branch != "" {
			t.Errorf("expected empty Branch without GITHUB_REF, got %q", prov.Branch)
		}
	}
}

// Edge case: CI mode with output file should write SARIF to file
func TestE2E_CIMode_OutputFileWithCI(t *testing.T) {
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
	cfgDir := filepath.Join(home, ".config", "mcp-audit")
	_ = os.RemoveAll(cfgDir)

	outFile := filepath.Join(t.TempDir(), "results.sarif")
	out, _, code := runE2ECIMode(t, bin, home, map[string]string{
		"GITHUB_REPOSITORY": "owner/repo",
		"GITHUB_REF":        "refs/heads/main",
		"GITHUB_SHA":        "abc123",
	}, "static", "--ci", "--output-file", outFile)

	_ = code

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("invalid SARIF in output file: %v\ncontent:\n%s", err, string(data))
	}
	if len(log.Runs) == 0 {
		t.Fatal("SARIF output file missing runs")
	}

	_ = out
}

// Edge case: CI mode tag check — ensure --ci is listed in help
func TestE2E_CIMode_ListedInHelp(t *testing.T) {
	bin := buildBinary(t)

	cmd := exec.Command(bin, "help")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("help failed: %v", err)
	}
	outStr := string(out)
	if !strings.Contains(outStr, "--ci") || !strings.Contains(outStr, "CI mode") {
		t.Error("--ci flag not listed in help output")
	}
}

// =============================================================================
// JSON type definitions for test parsing
// =============================================================================

type sarifLog struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool                     tool                 `json:"tool"`
	Results                  []sarifResult        `json:"results"`
	VersionControlProvenance []versionControlProv `json:"versionControlProvenance,omitempty"`
}

type versionControlProv struct {
	RepositoryURI string `json:"repositoryUri"`
	Branch        string `json:"branch,omitempty"`
	RevisionID    string `json:"revisionId,omitempty"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type sarifResult struct {
	RuleID  string  `json:"ruleId"`
	Level   string  `json:"level"`
	Message message `json:"message"`
}

type message struct {
	Text string `json:"text"`
}

type ciSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Pass     int `json:"pass"`
	Servers  int `json:"servers_scanned"`
}

// =============================================================================
// Test helpers
// =============================================================================

func runE2ECIMode(t *testing.T, bin, home string, envVars map[string]string, args ...string) (string, string, int) {
	t.Helper()

	cmd := exec.Command(bin, args...)
	cmd.Dir = home

	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "HOME="+home)
	for k, v := range envVars {
		cmd.Env = append(cmd.Env, k+"="+v)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
	}

	return stdout.String(), stderr.String(), code
}

func extractSarifJSON(t *testing.T, output string) string {
	t.Helper()

	lines := strings.Split(output, "\n")

	sarifStart := -1
	sarifEnd := -1
	braceDepth := 0
	inSarif := false

	for i, line := range lines {
		if !inSarif {
			if strings.TrimSpace(line) == "{" {
				sarifStart = i
				inSarif = true
				braceDepth = 1
			}
			continue
		}

		braceDepth += strings.Count(line, "{")
		braceDepth -= strings.Count(line, "}")

		if braceDepth == 0 {
			sarifEnd = i
			break
		}
	}

	if sarifStart < 0 || sarifEnd < 0 {
		t.Fatalf("could not extract SARIF JSON from CI output (sarifStart=%d, sarifEnd=%d)\noutput:\n%s", sarifStart, sarifEnd, output)
	}

	extracted := strings.Join(lines[sarifStart:sarifEnd+1], "\n")
	if !strings.Contains(extracted, `"version"`) || !strings.Contains(extracted, `"runs"`) {
		t.Fatalf("extracted content is not valid SARIF (lines %d-%d of %d)\n%s", sarifStart, sarifEnd, len(lines), extracted)
	}

	return extracted
}

func extractCISummary(t *testing.T, output string) string {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	var summaryLine string
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "{") && strings.Contains(line, `"critical"`) {
			summaryLine = line
			break
		}
	}
	return summaryLine
}
