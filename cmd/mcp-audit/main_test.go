package main

import (
	"bytes"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/mcheviron/mcp-audit/internal/report"
	"github.com/mcheviron/mcp-audit/internal/scanner"
)

func TestNewLoggerDefault(t *testing.T) {
	logger := newLogger(false, false, false)
	if logger == nil {
		t.Fatal("logger should not be nil")
	}
}

func TestNewLoggerVerbose(t *testing.T) {
	logger := newLogger(true, false, false)
	if logger == nil {
		t.Fatal("verbose logger should not be nil")
	}
}

func TestNewLoggerQuiet(t *testing.T) {
	logger := newLogger(false, true, false)
	if logger == nil {
		t.Fatal("quiet logger should not be nil")
	}
}

func TestNewLoggerDebug(t *testing.T) {
	logger := newLogger(false, false, true)
	if logger == nil {
		t.Fatal("debug logger should not be nil")
	}
}

func TestNewLoggerQuietTakesPriority(t *testing.T) {
	logger := newLogger(true, true, false)
	if logger == nil {
		t.Fatal("logger should not be nil")
	}
}

func TestSlogLevelsFilter(t *testing.T) {
	var buf bytes.Buffer
	level := slog.LevelInfo
	opts := &slog.HandlerOptions{Level: level}
	logger := slog.New(slog.NewTextHandler(&buf, opts))

	logger.Debug("debug msg")
	logger.Info("info msg")
	logger.Warn("warn msg")

	output := buf.String()
	if strings.Contains(output, "debug msg") {
		t.Error("INFO level should filter DEBUG messages")
	}
	if !strings.Contains(output, "info msg") {
		t.Error("INFO level should include INFO messages")
	}
	if !strings.Contains(output, "warn msg") {
		t.Error("INFO level should include WARN messages")
	}
}

func TestSlogQuietLevelFilter(t *testing.T) {
	var buf bytes.Buffer
	opts := &slog.HandlerOptions{Level: slog.LevelWarn}
	logger := slog.New(slog.NewTextHandler(&buf, opts))

	logger.Info("info msg")
	logger.Warn("warn msg")

	output := buf.String()
	if strings.Contains(output, "info msg") {
		t.Error("WARN level should filter INFO messages")
	}
	if !strings.Contains(output, "warn msg") {
		t.Error("WARN level should include WARN messages")
	}
}

func TestFilterBySeverity(t *testing.T) {
	results := []scanner.Result{
		{Severity: scanner.SevPass, Finding: "pass"},
		{Severity: scanner.SevCritical, Finding: "critical"},
		{Severity: scanner.SevInfo, Finding: "info"},
		{Severity: scanner.SevHigh, Finding: "high"},
	}

	filtered := filterBySeverity(results, scanner.SevHigh)
	for _, r := range filtered {
		if r.Severity < scanner.SevHigh {
			t.Errorf("HIGH filter should exclude severity %v: %s", r.Severity, r.Finding)
		}
	}
}

func TestWriteResultsOutputFile(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "mcp-audit-test-*.json")
	if err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()
	defer os.Remove(tmpfile.Name())

	f := flags{format: "json", outputFile: tmpfile.Name()}
	results := []scanner.Result{
		{Severity: scanner.SevInfo, Server: "test", Type: "static", Finding: "test finding"},
	}
	if _, err := writeResults(results, nil, f); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "test finding") {
		t.Error("output file should contain finding")
	}
}

func TestSplitKeyValue(t *testing.T) {
	m := splitKeyValue("Authorization=Bearer token, X-Key=value")
	if len(m) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(m))
	}
	if m["Authorization"] != "Bearer token" {
		t.Errorf("got %q", m["Authorization"])
	}
}

func TestSplitKeyValueEmpty(t *testing.T) {
	if splitKeyValue("") != nil {
		t.Error("empty input should return nil")
	}
}

func TestCIFlagForcesSARIF(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "mcp-audit-ci-test-*.sarif")
	if err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()
	defer os.Remove(tmpfile.Name())

	f := flags{
		format:     "table",
		outputFile: tmpfile.Name(),
		ci:         true,
		ciInfo:     report.CIInfo{Repo: "test/repo", Branch: "main", CommitSHA: "abc123", Enabled: true},
	}
	results := []scanner.Result{
		{Severity: scanner.SevCritical, Server: "test.example.com", Type: "dynamic", Finding: "SSRF found"},
	}
	if _, err := writeResults(results, nil, f); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, `"$schema"`) {
		t.Error("CI mode should produce SARIF output regardless of --format")
	}
	if !strings.Contains(content, `"versionControlProvenance"`) {
		t.Error("CI mode SARIF should include versionControlProvenance")
	}
	if !strings.Contains(content, "test/repo") {
		t.Error("CI mode SARIF should include repository URI")
	}
	if !strings.Contains(content, "abc123") {
		t.Error("CI mode SARIF should include commit SHA")
	}
}

func TestCIFlagSummaryOutput(t *testing.T) {
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	f := flags{
		format: "table",
		ci:     true,
	}
	results := []scanner.Result{
		{Severity: scanner.SevCritical, Server: "s1", Type: "static", Finding: "f1"},
		{Severity: scanner.SevHigh, Server: "s2", Type: "static", Finding: "f2"},
		{Severity: scanner.SevMedium, Server: "s1", Type: "dynamic", Finding: "f3"},
		{Severity: scanner.SevPass, Server: "s3", Type: "static", Finding: "f4"},
	}
	if _, err := writeResults(results, nil, f); err != nil {
		t.Fatal(err)
	}

	w.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	os.Stdout = oldStdout

	output := buf.String()
	if !strings.Contains(output, `"critical":1`) {
		t.Error("CI summary should contain critical count")
	}
	if !strings.Contains(output, `"high":1`) {
		t.Error("CI summary should contain high count")
	}
	if !strings.Contains(output, `"medium":1`) {
		t.Error("CI summary should contain medium count")
	}
	if !strings.Contains(output, `"pass":1`) {
		t.Error("CI summary should contain pass count")
	}
	if !strings.Contains(output, `"servers_scanned":3`) {
		t.Error("CI summary should contain unique server count")
	}
}

func TestCIFlagNoProvenanceWithoutEnvVars(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "mcp-audit-ci-test-*.sarif")
	if err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()
	defer os.Remove(tmpfile.Name())

	f := flags{
		format:     "sarif",
		outputFile: tmpfile.Name(),
		ci:         true,
	}
	results := []scanner.Result{
		{Severity: scanner.SevInfo, Server: "test.example.com", Type: "static", Finding: "info"},
	}
	if _, err := writeResults(results, nil, f); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if strings.Contains(content, `"versionControlProvenance"`) {
		t.Error("SARIF should NOT include versionControlProvenance when repo is absent")
	}
}

func TestCIInfoEnvVars(t *testing.T) {
	os.Setenv("GITHUB_REPOSITORY", "org/repo")
	os.Setenv("GITHUB_REF", "refs/heads/feature-branch")
	os.Setenv("GITHUB_SHA", "def4567890abcdef")
	defer func() {
		os.Unsetenv("GITHUB_REPOSITORY")
		os.Unsetenv("GITHUB_REF")
		os.Unsetenv("GITHUB_SHA")
	}()

	f := flags{formatRaw: "table", probeDepthRaw: "basic", ci: true}
	if err := validateAndApply(nil, &f); err != nil {
		t.Fatal(err)
	}
	if !f.ci {
		t.Error("--ci flag should set ci to true")
	}
	if f.ciInfo.Repo != "org/repo" {
		t.Errorf("expected 'org/repo', got %q", f.ciInfo.Repo)
	}
	if f.ciInfo.Branch != "feature-branch" {
		t.Errorf("expected 'feature-branch', got %q", f.ciInfo.Branch)
	}
	if f.ciInfo.CommitSHA != "def4567890abcdef" {
		t.Errorf("expected 'def4567890abcdef', got %q", f.ciInfo.CommitSHA)
	}
}

func TestParseFlagsWithCI(t *testing.T) {
	f := flags{formatRaw: "table", probeDepthRaw: "basic", ci: true}
	if err := validateAndApply(nil, &f); err != nil {
		t.Fatal(err)
	}
	if !f.ci {
		t.Error("--ci flag should set ci to true")
	}
}

func TestParseFlagsMinSecurityScore(t *testing.T) {
	f := flags{formatRaw: "table", probeDepthRaw: "basic", minSecurityScore: 75}
	if err := validateAndApply(nil, &f); err != nil {
		t.Fatal(err)
	}
	if f.minSecurityScore != 75 {
		t.Errorf("expected minSecurityScore 75, got %f", f.minSecurityScore)
	}
}

func TestParseFlagsMaxAbsoluteRisk(t *testing.T) {
	f := flags{formatRaw: "table", probeDepthRaw: "basic", maxAbsoluteRisk: 30}
	if err := validateAndApply(nil, &f); err != nil {
		t.Fatal(err)
	}
	if f.maxAbsoluteRisk != 30 {
		t.Errorf("expected maxAbsoluteRisk 30, got %f", f.maxAbsoluteRisk)
	}
}

func TestParseFlagsHeuristic(t *testing.T) {
	f := flags{formatRaw: "table", probeDepthRaw: "basic", heuristic: false}
	if err := validateAndApply(nil, &f); err != nil {
		t.Fatal(err)
	}
	if f.heuristic {
		t.Error("expected heuristic to be false")
	}
}

func TestParseFlagsScoreWeights(t *testing.T) {
	f := flags{formatRaw: "table", probeDepthRaw: "basic", scoreWeights: "0.30,0.25,0.20,0.15,0.10"}
	if err := validateAndApply(nil, &f); err != nil {
		t.Fatal(err)
	}
	if f.scoreWeights != "0.30,0.25,0.20,0.15,0.10" {
		t.Errorf("unexpected scoreWeights: %s", f.scoreWeights)
	}
}

func TestParseFlagsLLMEndpoint(t *testing.T) {
	f := flags{formatRaw: "table", probeDepthRaw: "basic", llmEndpoint: "http://localhost:9999"}
	if err := validateAndApply(nil, &f); err != nil {
		t.Fatal(err)
	}
	if f.llmEndpoint != "http://localhost:9999" {
		t.Errorf("expected llmEndpoint, got %q", f.llmEndpoint)
	}
}

func TestParseFlagsHeuristicDefaultTrue(t *testing.T) {
	f := flags{formatRaw: "table", probeDepthRaw: "basic", heuristic: true}
	if err := validateAndApply(nil, &f); err != nil {
		t.Fatal(err)
	}
	if !f.heuristic {
		t.Error("heuristic should default to true")
	}
}

func TestParseFlagsMaxAbsoluteRiskDefault(t *testing.T) {
	f := flags{formatRaw: "table", probeDepthRaw: "basic", maxAbsoluteRisk: 100}
	if err := validateAndApply(nil, &f); err != nil {
		t.Fatal(err)
	}
	if f.maxAbsoluteRisk != 100 {
		t.Errorf("maxAbsoluteRisk should default to 100, got %f", f.maxAbsoluteRisk)
	}
}
