package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/mcheviron/mcp-audit/internal/report"
	"github.com/mcheviron/mcp-audit/internal/scanner"
)

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	fn()
	w.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	os.Stderr = old
	return buf.String()
}

func TestWriteResultsHeaderFooterTally(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "mcp-audit-tally-*.out")
	if err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()
	defer os.Remove(tmpfile.Name())

	f := flags{format: "table", outputFile: tmpfile.Name()}
	results := []scanner.Result{
		{Severity: scanner.SevCritical, Server: "a", Type: "static", Finding: "f1"},
		{Severity: scanner.SevCritical, Server: "b", Type: "static", Finding: "f2"},
		{Severity: scanner.SevHigh, Server: "c", Type: "static", Finding: "f3"},
		{Severity: scanner.SevPass, Server: "d", Type: "static", Finding: "f4"},
		{Severity: scanner.SevPass, Server: "e", Type: "static", Finding: "f5"},
	}
	displayed, err := writeResults(results, nil, f)
	if err != nil {
		t.Fatal(err)
	}

	footer := captureStderr(t, func() {
		report.PrintSummary(displayed, len(results))
	})

	headerData, err := os.ReadFile(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}
	header := string(headerData)

	headerSummary := "Summary: 2 CRITICAL  1 HIGH  0 MEDIUM  0 LOW  0 INFO  2 PASS"
	if !strings.Contains(header, headerSummary) {
		t.Errorf("header missing expected summary\nwant: %q\ngot:  %s", headerSummary, header)
	}

	footerTally := "2 CRITICAL  1 HIGH  0 MEDIUM  0 LOW  0 INFO  2 PASS  —  5 servers scanned"
	if !strings.Contains(footer, footerTally) {
		t.Errorf("footer missing expected tally\nwant: %q\ngot:  %s", footerTally, footer)
	}
}

func TestWriteResultsHeaderFooterTallyAfterFilter(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "mcp-audit-tally-*.out")
	if err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()
	defer os.Remove(tmpfile.Name())

	f := flags{format: "table", outputFile: tmpfile.Name(), severityMin: scanner.SevHigh}
	results := []scanner.Result{
		{Severity: scanner.SevCritical, Server: "a", Type: "static", Finding: "f1"},
		{Severity: scanner.SevCritical, Server: "b", Type: "static", Finding: "f2"},
		{Severity: scanner.SevHigh, Server: "c", Type: "static", Finding: "f3"},
		{Severity: scanner.SevPass, Server: "d", Type: "static", Finding: "f4"},
	}
	displayed, err := writeResults(results, nil, f)
	if err != nil {
		t.Fatal(err)
	}

	footer := captureStderr(t, func() {
		report.PrintSummary(displayed, len(results))
	})

	headerData, err := os.ReadFile(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}
	header := string(headerData)

	filtered := "Summary: 2 CRITICAL  1 HIGH  0 MEDIUM  0 LOW  0 INFO  0 PASS"
	if !strings.Contains(header, filtered) {
		t.Errorf("filtered header missing expected summary\nwant: %q\ngot:  %s", filtered, header)
	}

	filteredFooter := "2 CRITICAL  1 HIGH  0 MEDIUM  0 LOW  0 INFO  0 PASS  —  4 servers scanned"
	if !strings.Contains(footer, filteredFooter) {
		t.Errorf("filtered footer missing expected tally\nwant: %q\ngot:  %s", filteredFooter, footer)
	}
}

func TestWriteResultsDedupFooterMatches(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "mcp-audit-tally-*.out")
	if err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()
	defer os.Remove(tmpfile.Name())

	f := flags{format: "table", outputFile: tmpfile.Name()}
	results := []scanner.Result{
		{Severity: scanner.SevCritical, Server: "a", Type: "static", Finding: "API key detected in /tmp/x.json"},
		{Severity: scanner.SevCritical, Server: "a", Type: "static", Finding: "API key detected in /tmp/x.json"},
		{Severity: scanner.SevCritical, Server: "a", Type: "static", Finding: "API key detected in /tmp/x.json"},
		{Severity: scanner.SevPass, Server: "b", Type: "static", Finding: "package not in trust lists"},
	}
	displayed, err := writeResults(results, nil, f)
	if err != nil {
		t.Fatal(err)
	}

	footer := captureStderr(t, func() {
		report.PrintSummary(displayed, len(results))
	})

	headerData, err := os.ReadFile(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}
	header := string(headerData)

	wantHeader := "Summary: 1 CRITICAL  0 HIGH  0 MEDIUM  0 LOW  0 INFO  1 PASS"
	if !strings.Contains(header, wantHeader) {
		t.Errorf("deduped header missing expected summary\nwant: %q\ngot:  %s", wantHeader, header)
	}

	wantFooter := "1 CRITICAL  0 HIGH  0 MEDIUM  0 LOW  0 INFO  1 PASS  —  4 servers scanned"
	if !strings.Contains(footer, wantFooter) {
		t.Errorf("deduped footer missing expected tally\nwant: %q\ngot:  %s", wantFooter, footer)
	}
}

func TestWriteResultsEmpty(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "mcp-audit-tally-*.out")
	if err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()
	defer os.Remove(tmpfile.Name())

	f := flags{format: "table", outputFile: tmpfile.Name()}
	displayed, err := writeResults(nil, nil, f)
	if err != nil {
		t.Fatalf("writeResults on empty input returned err: %v", err)
	}

	footer := captureStderr(t, func() {
		report.PrintSummary(displayed, 0)
	})

	headerData, err := os.ReadFile(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}
	header := string(headerData)

	if strings.Contains(header, "Summary:") {
		t.Errorf("clean run should suppress Summary header, got %q", header)
	}
	if !strings.Contains(footer, "0 findings") {
		t.Errorf("clean run footer should be 0 findings line, got %q", footer)
	}
}
