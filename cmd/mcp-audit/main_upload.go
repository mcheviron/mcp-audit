package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mostafaelataby-cheviron/mcp-audit/internal/scanner"
)

var communityUploadURL = "https://mcp-audit-db.vercel.app/api/report"

var hostTLDs = []string{
	".com", ".org", ".net", ".io", ".dev", ".local", ".internal", ".app",
	".svc", ".cluster.local", ".corp", ".lan", ".lab", ".test", ".localhost",
}

type anonFinding struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Finding  string `json:"finding"`
	Detail   string `json:"detail,omitempty"`
}

type uploadPayload struct {
	Version  string        `json:"version"`
	Tool     string        `json:"tool"`
	Findings []anonFinding `json:"findings"`
}

func runUpload(args []string) {
	f, err := parseFlags(args)
	if err != nil {
		os.Exit(2)
	}
	applyConfigDefaults(&f)

	logger := newLogger(f.verbose, f.quiet, f.debug)
	logger.Debug("starting upload")

	s := scanner.NewScanner()
	s.NoSecretScan = f.noSecretScan
	if err := s.SetTrustConfig(f.trustConfig); err != nil {
		if f.trustConfig != "" {
			logger.Error("trust config error", "error", err)
			os.Exit(4)
		}
	}

	results, err := s.Static()
	if err != nil {
		logger.Error("scan failed", "error", err)
		os.Exit(4)
	}

	payload := anonymizeFindings(results.Results)
	if len(payload.Findings) == 0 {
		fmt.Println("No findings to upload.")
		return
	}

	displayPayload(payload)

	fmt.Print("\nUpload these anonymized findings to community DB? [y/N]: ")
	if !readYes() {
		fmt.Println("Upload cancelled.")
		return
	}

	if err := postPayload(communityUploadURL, payload); err != nil {
		fmt.Fprintf(os.Stderr, "upload: POST failed: %v\n", err)
		fmt.Println("Findings could not be uploaded. You can submit them manually at:")
		fmt.Println("  https://github.com/mcp-audit-db/issues/new")
		os.Exit(4)
	}

	fmt.Println("Upload complete. Thank you for contributing to the community DB.")
}

func anonymizeFindings(results []scanner.Result) uploadPayload {
	payload := uploadPayload{
		Version: "1.0.0",
		Tool:    "mcp-audit",
	}

	seen := make(map[string]bool)

	for _, r := range results {
		if r.Severity == scanner.SevPass {
			continue
		}

		sanitizedFinding := sanitizeDetail(r.Finding)
		key := r.Type + "|" + r.Severity.String() + "|" + sanitizedFinding
		if seen[key] {
			continue
		}
		seen[key] = true

		detail := sanitizeDetail(r.Detail)

		payload.Findings = append(payload.Findings, anonFinding{
			Type:     r.Type,
			Severity: r.Severity.String(),
			Finding:  sanitizedFinding,
			Detail:   detail,
		})
	}

	return payload
}

func sanitizeDetail(detail string) string {
	words := strings.Fields(detail)
	var cleaned []string
	var redacted bool
	for _, w := range words {
		if looksLikeHost(w) || looksLikeIP(w) || looksLikeURL(w) {
			cleaned = append(cleaned, "[REDACTED]")
			redacted = true
			continue
		}
		cleaned = append(cleaned, w)
	}
	if !redacted {
		return detail
	}
	return strings.Join(cleaned, " ")
}

func looksLikeHost(s string) bool {
	if s == "" {
		return false
	}
	cleaned := strings.TrimRight(s, ".:;,'\"")
	cleaned = stripPort(cleaned)
	lower := strings.ToLower(cleaned)
	for _, tld := range hostTLDs {
		if strings.HasSuffix(lower, tld) {
			return true
		}
	}
	return strings.HasSuffix(lower, ".internal")
}

func stripPort(s string) string {
	if colon := strings.LastIndex(s, ":"); colon > 0 {
		if port := s[colon+1:]; isAllDigits(port) {
			return s[:colon]
		}
	}
	return s
}

func looksLikeIP(s string) bool {
	s = strings.TrimRight(s, "/:.,;'\"")
	if colon := strings.LastIndex(s, ":"); colon > 0 {
		if port := s[colon+1:]; isAllDigits(port) {
			s = s[:colon]
		}
	}
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if !isAllDigits(p) || p == "" {
			return false
		}
	}
	return true
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func looksLikeURL(s string) bool {
	s = strings.TrimRight(s, ",;'\"")
	s = strings.ToLower(s)
	return strings.HasPrefix(s, "http://") ||
		strings.HasPrefix(s, "https://") ||
		strings.HasPrefix(s, "ws://")
}

func displayPayload(payload uploadPayload) {
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "upload: display error: %v\n", err)
		return
	}
	fmt.Println("Data to be uploaded:")
	fmt.Println(string(data))
}

func postPayload(url string, payload uploadPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("POST %s: HTTP %d: %s", url, resp.StatusCode, string(respBody))
	}

	return nil
}
