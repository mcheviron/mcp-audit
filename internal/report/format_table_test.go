package report

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/mcheviron/mcp-audit/internal/scanner"
)

func TestWriteTableFileSubHeaders(t *testing.T) {
	results := []scanner.Result{
		{Severity: scanner.SevPass, Server: "a", Finding: "x",
			ConfigPath: "/path/one.json", Scope: "project"},
		{Severity: scanner.SevPass, Server: "b", Finding: "y",
			ConfigPath: "/path/two.json", Scope: "project"},
		{Severity: scanner.SevPass, Server: "c", Finding: "z",
			ConfigPath: "/path/one.json", Scope: "project"},
	}
	var buf bytes.Buffer
	if err := writeTable(&buf, results, nil, TableOptions{Width: 100}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if c := strings.Count(out, "/path/one.json"); c != 1 {
		t.Errorf("expected /path/one.json once, got %d", c)
	}
	if c := strings.Count(out, "/path/two.json"); c != 1 {
		t.Errorf("expected /path/two.json once, got %d", c)
	}
}

func TestWriteTableRemediationIndentedUnderFinding(t *testing.T) {
	results := []scanner.Result{
		{
			Severity:    scanner.SevCritical,
			Server:      "srv",
			Finding:     "finding text",
			Remediation: "rem text",
		},
	}
	var buf bytes.Buffer
	if err := writeTable(&buf, results, nil, TableOptions{Width: 100}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "↳ Remediation:") || !strings.Contains(out, "rem text") {
		t.Errorf("expected indented remediation, got %q", out)
	}
	remIdx := strings.Index(out, "↳ Remediation:")
	rowStart := strings.LastIndex(out[:remIdx], "\n") + 1
	indent := remIdx - rowStart
	if indent == 0 {
		t.Error("remediation line should be indented, not at col 0")
	}
}

func TestWriteTableServerColumnAligned(t *testing.T) {
	results := []scanner.Result{
		{Severity: scanner.SevPass, Server: "a", Finding: "first"},
		{Severity: scanner.SevPass, Server: "medium-name", Finding: "second"},
		{Severity: scanner.SevPass, Server: "very-long-server-name", Finding: "third"},
	}
	var buf bytes.Buffer
	if err := writeTable(&buf, results, nil, TableOptions{Width: 100}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	cols := []int{colOf(t, out, "first"), colOf(t, out, "second"), colOf(t, out, "third")}
	if cols[0] != cols[1] || cols[1] != cols[2] {
		t.Errorf("finding column should align: %v", cols)
	}
}

func TestWriteTableNoConfigPathRows(t *testing.T) {
	results := []scanner.Result{
		{Severity: scanner.SevPass, Server: "a", Finding: "x"},
	}
	var buf bytes.Buffer
	if err := writeTable(&buf, results, nil, TableOptions{Width: 100}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "── PASS ──") {
		t.Errorf("expected PASS heading, got %q", out)
	}
	if !strings.Contains(out, "PASS") || !strings.Contains(out, "a") {
		t.Errorf("expected row printed, got %q", out)
	}
}

func TestWriteTableGroupBlankLines(t *testing.T) {
	results := []scanner.Result{
		{Severity: scanner.SevCritical, Server: "a", Finding: "x"},
		{Severity: scanner.SevHigh, Server: "b", Finding: "y"},
		{Severity: scanner.SevPass, Server: "c", Finding: "z"},
	}
	var buf bytes.Buffer
	if err := writeTable(&buf, results, nil, TableOptions{Width: 100}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if c := strings.Count(out, "── CRITICAL ──"); c != 1 {
		t.Errorf("expected 1 CRITICAL heading, got %d", c)
	}
	if c := strings.Count(out, "── HIGH ──"); c != 1 {
		t.Errorf("expected 1 HIGH heading, got %d", c)
	}
	if c := strings.Count(out, "── PASS ──"); c != 1 {
		t.Errorf("expected 1 PASS heading, got %d", c)
	}
	critIdx := strings.Index(out, "── CRITICAL ──")
	highIdx := strings.Index(out, "── HIGH ──")
	passIdx := strings.Index(out, "── PASS ──")
	if !(critIdx < highIdx && highIdx < passIdx) {
		t.Error("severity groups should be in canonical order")
	}
}

func TestWriteSummaryLineSuppressedWhenAllZero(t *testing.T) {
	counts := map[scanner.Severity]int{}
	var buf bytes.Buffer
	if err := writeSummaryLine(&buf, counts); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected empty output for all-zero counts, got %q", buf.String())
	}
}

func TestWriteSummaryLineRendersNonZero(t *testing.T) {
	counts := map[scanner.Severity]int{
		scanner.SevCritical: 1,
	}
	var buf bytes.Buffer
	if err := writeSummaryLine(&buf, counts); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Summary: 1 CRITICAL") {
		t.Errorf("expected Summary line, got %q", buf.String())
	}
}

func TestAllZero(t *testing.T) {
	if !allZero(map[scanner.Severity]int{}) {
		t.Error("empty map should be all zero")
	}
	if !allZero(nil) {
		t.Error("nil map should be all zero")
	}
	if !allZero(map[scanner.Severity]int{scanner.SevPass: 0}) {
		t.Error("map with explicit zero should still be all zero")
	}
	if allZero(map[scanner.Severity]int{scanner.SevCritical: 1}) {
		t.Error("map with one non-zero should not be all zero")
	}
}

func TestPrintSummaryCleanRun(t *testing.T) {
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w

	PrintSummary(nil, 5)

	w.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	os.Stderr = oldStderr

	got := buf.String()
	want := "0 findings — 5 servers scanned\n"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestPrintSummaryNonZero(t *testing.T) {
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w

	PrintSummary([]scanner.Result{
		{Severity: scanner.SevCritical, Server: "a"},
	}, 7)

	w.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	os.Stderr = oldStderr

	got := buf.String()
	if !strings.Contains(got, "1 CRITICAL") {
		t.Errorf("expected 1 CRITICAL in footer, got %q", got)
	}
	if !strings.Contains(got, "7 servers scanned") {
		t.Errorf("expected 7 servers scanned in footer, got %q", got)
	}
	if strings.Contains(got, "0 findings —") {
		t.Error("non-zero run should not emit clean-run line")
	}
}

func TestWriteTableWrapsLongRemediation(t *testing.T) {
	long := strings.Repeat("alpha bravo charlie delta echo foxtrot ", 5)
	results := []scanner.Result{
		{
			Severity:    scanner.SevCritical,
			Server:      "s1",
			Finding:     "f",
			Remediation: long,
		},
	}
	var buf bytes.Buffer
	if err := writeTable(&buf, results, nil, TableOptions{Width: 80}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for i, line := range strings.Split(out, "\n") {
		if len(line) > 95 {
			t.Errorf("line %d exceeds 95 chars (%d): %q", i, len(line), line)
		}
	}
	if !strings.Contains(out, "Remediation:") {
		t.Error("expected Remediation: in output")
	}
}

func TestWriteTableWrapsLongDetail(t *testing.T) {
	long := strings.Repeat("token123 abcdef xyzpdq ", 6)
	results := []scanner.Result{
		{
			Severity: scanner.SevHigh,
			Server:   "s1",
			Finding:  "f",
			Detail:   long,
		},
	}
	var buf bytes.Buffer
	if err := writeTable(&buf, results, nil, TableOptions{Width: 80}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for i, line := range strings.Split(out, "\n") {
		if len(line) > 95 {
			t.Errorf("line %d exceeds 95 chars (%d): %q", i, len(line), line)
		}
	}
}

func TestWriteTableSkipsPassRemediationByDefault(t *testing.T) {
	results := []scanner.Result{
		{
			Severity:    scanner.SevPass,
			Server:      "s1",
			Finding:     "f",
			Remediation: "this should not appear",
		},
	}
	var buf bytes.Buffer
	if err := writeTable(&buf, results, nil, TableOptions{Width: 100}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "this should not appear") {
		t.Error("PASS Remediation leaked when ShowPassRemediation=false")
	}
	if strings.Contains(buf.String(), "Remediation:") {
		t.Error("PASS Remediation line emitted when ShowPassRemediation=false")
	}
}

func TestWriteTableShowsPassRemediationWhenEnabled(t *testing.T) {
	results := []scanner.Result{
		{
			Severity:    scanner.SevPass,
			Server:      "s1",
			Finding:     "f",
			Remediation: "visible-marker-xyz",
		},
	}
	var buf bytes.Buffer
	if err := writeTable(&buf, results, nil,
		TableOptions{Width: 100, ShowPassRemediation: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "visible-marker-xyz") {
		t.Errorf("expected PASS Remediation when flag enabled, got %q", buf.String())
	}
}

func TestWrapText(t *testing.T) {
	cases := []struct {
		name  string
		input string
		width int
		want  int
	}{
		{"short", "hello world", 80, 1},
		{"two lines", "aaa bbb ccc ddd eee fff ggg", 15, 2},
		{"paragraphs", "aaa bbb\nccc ddd", 80, 1},
		{"long paragraph", "aaa bbb ccc ddd eee fff ggg hhh", 10, 4},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := wrapText(tt.input, tt.width)
			if len(got) != tt.want {
				t.Errorf("got %d lines, want %d: %v", len(got), tt.want, got)
			}
			for _, line := range got {
				if len(line) > tt.width {
					t.Errorf("line exceeds width %d: %q", tt.width, line)
				}
			}
		})
	}
}

func TestContentWidth(t *testing.T) {
	if got := contentWidth(0, 50); got < 20 {
		t.Errorf("contentWidth(0, 50) too small: %d", got)
	}
	if got := contentWidth(80, 70); got != 20 {
		t.Errorf("contentWidth(80, 70) = %d, want min 20", got)
	}
	if got := contentWidth(200, 30); got <= 0 {
		t.Errorf("contentWidth(200, 30) = %d, want > 0", got)
	}
}

func TestWriteTableWrapsLongFinding(t *testing.T) {
	long := strings.Repeat("alpha bravo charlie delta echo foxtrot ", 5)
	results := []scanner.Result{
		{
			Severity: scanner.SevHigh,
			Server:   "s1",
			Finding:  long,
		},
	}
	var buf bytes.Buffer
	if err := writeTable(&buf, results, nil, TableOptions{Width: 80}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		if len(line) > 95 {
			t.Errorf("line %d exceeds 95 chars (%d): %q", i, len(line), line)
		}
	}
	if !strings.Contains(out, "alpha bravo") {
		t.Error("expected finding text in output")
	}
	firstCol := colOf(t, out, "alpha bravo")
	secondCol := -1
	for _, line := range lines {
		if strings.HasPrefix(line, "HIGH") {
			continue
		}
		if idx := strings.Index(line, "foxtrot"); idx >= 0 {
			secondCol = idx
			break
		}
	}
	if secondCol < 0 {
		t.Fatal("expected foxtrot on a continuation line")
	}
	if firstCol != secondCol {
		t.Errorf("continuation column (%d) should equal finding column (%d)",
			secondCol, firstCol)
	}
	wantIndent := strings.Repeat(" ", firstCol)
	if !strings.Contains(out, "\n"+wantIndent+"foxtrot") {
		t.Errorf("expected continuation line starting with %d-space indent under finding column", firstCol)
	}
}

func TestWriteTableShortFindingStaysOneLine(t *testing.T) {
	results := []scanner.Result{
		{
			Severity: scanner.SevPass,
			Server:   "short",
			Finding:  "ok",
		},
	}
	var buf bytes.Buffer
	if err := writeTable(&buf, results, nil, TableOptions{Width: 100}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if c := strings.Count(out, "ok\n"); c != 1 {
		t.Errorf("expected finding 'ok' on exactly one line, got %d occurrences", c)
	}
}

func TestWriteTableFindingAtWidthBoundary(t *testing.T) {
	finding := strings.Repeat("w", 60)
	results := []scanner.Result{
		{
			Severity: scanner.SevPass,
			Server:   "s",
			Finding:  finding,
		},
	}
	var buf bytes.Buffer
	if err := writeTable(&buf, results, nil, TableOptions{Width: 80}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, finding) {
		t.Errorf("expected finding %q in output, got %q", finding, out)
	}
	if c := strings.Count(out, finding); c != 1 {
		t.Errorf("expected finding to appear exactly once (single line), got %d times", c)
	}
	for i, line := range strings.Split(out, "\n") {
		if len(line) > 95 {
			t.Errorf("line %d exceeds 95 chars (%d)", i, len(line))
		}
	}
}

func TestWrapTextBreaksLongToken(t *testing.T) {
	long := strings.Repeat("a", 250)
	lines := wrapText(long, 80)
	if len(lines) < 4 {
		t.Fatalf("expected long token broken, got %d lines", len(lines))
	}
	for i, line := range lines {
		if len(line) > 80 {
			t.Errorf("line %d exceeds width 80: len=%d", i, len(line))
		}
	}
}

func TestWriteTableBreaksLongFinding(t *testing.T) {
	finding := strings.Repeat("z", 210)
	results := []scanner.Result{
		{Severity: scanner.SevCritical, Server: "s1", Finding: finding},
	}
	var buf bytes.Buffer
	if err := writeTable(&buf, results, nil, TableOptions{Width: 100}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for i, line := range strings.Split(out, "\n") {
		if len(line) > 120 {
			t.Errorf("line %d exceeds 120 chars (%d)", i, len(line))
		}
	}
	if c := strings.Count(out, "z"); c != 210 {
		t.Errorf("expected 210 z chars preserved, got %d", c)
	}
}

func TestWriteTableEmbeddedNewlineFindsColumnZero(t *testing.T) {
	results := []scanner.Result{
		{Severity: scanner.SevHigh, Server: "s1", Finding: "a\n\nb"},
	}
	var buf bytes.Buffer
	if err := writeTable(&buf, results, nil, TableOptions{Width: 100}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for i, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "        ") {
			t.Errorf("line %d has indented blank: %q", i, line)
		}
	}
}

func colOf(t *testing.T, out, marker string) int {
	t.Helper()
	idx := strings.Index(out, marker)
	if idx < 0 {
		t.Fatalf("marker %q not found", marker)
	}
	lineStart := strings.LastIndex(out[:idx], "\n") + 1
	return idx - lineStart
}
