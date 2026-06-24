package report

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/mcheviron/mcp-audit/internal/scanner"
)

type junitTestSuite struct {
	XMLName   xml.Name        `xml:"testsuite"`
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Errors    int             `xml:"errors,attr"`
	Skipped   int             `xml:"skipped,attr"`
	Timestamp string          `xml:"timestamp,attr"`
	Time      string          `xml:"time,attr"`
	TestCases []junitTestCase `xml:"testcase"`
}

type junitTestCase struct {
	Name    string        `xml:"name,attr"`
	Time    string        `xml:"time,attr"`
	Failure *junitFailure `xml:"failure,omitempty"`
	Error   *junitError   `xml:"error,omitempty"`
	Skipped *junitSkipped `xml:"skipped,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Text    string `xml:",cdata"`
}

type junitError struct {
	Message string `xml:"message,attr"`
	Text    string `xml:",cdata"`
}

type junitSkipped struct {
	Message string `xml:"message,attr"`
}

func writeJUnit(w io.Writer, results []scanner.Result) error {
	failures := 0
	errors := 0
	skipped := 0
	cases := make([]junitTestCase, 0, len(results))

	for _, r := range results {
		name := fmt.Sprintf("%s: %s", r.Server, r.Finding)
		tc := junitTestCase{
			Name: name,
			Time: "0.000",
		}

		switch r.Severity {
		case scanner.SevCritical, scanner.SevHigh:
			failures++
			tc.Failure = &junitFailure{
				Message: r.Severity.String(),
				Text:    junitMessageText(r),
			}
		case scanner.SevMedium:
			errors++
			tc.Error = &junitError{
				Message: r.Severity.String(),
				Text:    junitMessageText(r),
			}
		case scanner.SevLow, scanner.SevInfo:
			skipped++
			tc.Skipped = &junitSkipped{
				Message: r.Severity.String(),
			}
		case scanner.SevPass:
		}

		cases = append(cases, tc)
	}

	ts := junitTestSuite{
		Name:      "mcp-audit",
		Tests:     len(results),
		Failures:  failures,
		Errors:    errors,
		Skipped:   skipped,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Time:      "0.000",
		TestCases: cases,
	}

	out, err := xml.MarshalIndent(ts, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write([]byte(xml.Header + string(out)))
	return err
}

func junitMessageText(r scanner.Result) string {
	t := fmt.Sprintf("[%s] %s: %s", r.Severity, r.Server, r.Finding)
	if r.Detail != "" {
		t += "\nDetail: " + r.Detail
	}
	if r.Remediation != "" {
		t += "\nRemediation: " + r.Remediation
	}
	return sanitizeCDATA(t)
}

func sanitizeCDATA(s string) string {
	return strings.ReplaceAll(s, "]]>", "]]]]><![CDATA[>")
}
