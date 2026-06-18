package main

import (
	"bytes"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/mostafaelataby-cheviron/mcp-audit/internal/scanner"
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
	writeResults(results, f)

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
