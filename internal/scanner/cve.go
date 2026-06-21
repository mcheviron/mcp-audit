package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type CVEEntry struct {
	ID          string
	CVSSScore   float64
	Description string
	Published   string
	URL         string
}

type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID          string `json:"id"`
			Description struct {
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
			} `json:"descriptions"`
			Metrics struct {
				CVSSv31 []struct {
					BaseScore float64 `json:"baseScore"`
				} `json:"cvssMetricV31"`
				CVSSv30 []struct {
					BaseScore float64 `json:"baseScore"`
				} `json:"cvssMetricV30"`
				CVSSv20 []struct {
					BaseScore float64 `json:"baseScore"`
				} `json:"cvssMetricV2"`
			} `json:"metrics"`
			Published string `json:"published"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

type ghAdvisoryResponse []struct {
	CVEID       string  `json:"cve_id"`
	Summary     string  `json:"summary"`
	Description string  `json:"description"`
	CVSSScore   float64 `json:"cvss_score"`
	PublishedAt string  `json:"published_at"`
	HTMLURL     string  `json:"html_url"`
}

var (
	nvdBaseURL        = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	ghAdvisoryBaseURL = "https://api.github.com/advisories"
)

const (
	cveClientTimeout  = 10 * time.Second
	cveRateLimitDelay = 1 * time.Second
)

var cveHTTPClient = &http.Client{Timeout: cveClientTimeout}

func queryNVD(packageName string) ([]CVEEntry, error) {
	u, err := url.Parse(nvdBaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse NVD URL: %w", err)
	}
	q := u.Query()
	q.Set("keywordSearch", packageName)
	q.Set("resultsPerPage", "5")
	u.RawQuery = q.Encode()

	ctx, cancel := context.WithTimeout(context.Background(), cveClientTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("NVD request: %w", err)
	}
	resp, err := cveHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("NVD request: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			_ = cerr
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("NVD read body: %w", err)
	}

	var nvd nvdResponse
	if err := json.Unmarshal(body, &nvd); err != nil {
		return nil, fmt.Errorf("NVD parse JSON: %w", err)
	}

	var entries []CVEEntry
	for _, vuln := range nvd.Vulnerabilities {
		entry := CVEEntry{
			ID:        vuln.CVE.ID,
			Published: vuln.CVE.Published,
			URL:       fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", vuln.CVE.ID),
		}

		for _, d := range vuln.CVE.Description.Descriptions {
			if d.Lang == "en" {
				entry.Description = d.Value
				break
			}
		}

		entry.CVSSScore = extractCVSS(vuln.CVE.Metrics)
		entries = append(entries, entry)
	}

	return entries, nil
}

func queryGitHubAdvisory(packageName, ecosystem string) ([]CVEEntry, error) { //nolint:funlen
	u, err := url.Parse(ghAdvisoryBaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse GitHub Advisory URL: %w", err)
	}
	q := u.Query()
	q.Set("type", "reviewed")
	if ecosystem != "" {
		q.Set("ecosystem", ecosystem)
	}
	q.Set("affects", packageName)
	u.RawQuery = q.Encode()

	ctx, cancel := context.WithTimeout(context.Background(), cveClientTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("GitHub Advisory request: %w", err)
	}
	req.Header.Set("User-Agent", "mcp-audit/0.1.0")
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := cveHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GitHub Advisory request: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			_ = cerr
		}
	}()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("GitHub Advisory rate limited (status %d)", resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub Advisory API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("GitHub Advisory read body: %w", err)
	}

	var advisories ghAdvisoryResponse
	if err := json.Unmarshal(body, &advisories); err != nil {
		return nil, fmt.Errorf("GitHub Advisory parse JSON: %w", err)
	}

	var entries []CVEEntry
	for _, adv := range advisories {
		id := adv.CVEID
		if id == "" {
			continue
		}
		entry := CVEEntry{
			ID:          id,
			Description: adv.Summary,
			Published:   adv.PublishedAt,
			CVSSScore:   adv.CVSSScore,
			URL:         adv.HTMLURL,
		}
		if entry.Description == "" {
			entry.Description = adv.Description
		}
		if entry.URL == "" {
			entry.URL = fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", id)
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

func extractCVSS(metrics struct {
	CVSSv31 []struct {
		BaseScore float64 `json:"baseScore"`
	} `json:"cvssMetricV31"`
	CVSSv30 []struct {
		BaseScore float64 `json:"baseScore"`
	} `json:"cvssMetricV30"`
	CVSSv20 []struct {
		BaseScore float64 `json:"baseScore"`
	} `json:"cvssMetricV2"`
}) float64 {
	if len(metrics.CVSSv31) > 0 {
		return metrics.CVSSv31[0].BaseScore
	}
	if len(metrics.CVSSv30) > 0 {
		return metrics.CVSSv30[0].BaseScore
	}
	if len(metrics.CVSSv20) > 0 {
		return metrics.CVSSv20[0].BaseScore
	}
	return 0
}

func cveSeverity(cvssScore float64) Severity {
	switch {
	case cvssScore >= 9.0:
		return SevCritical
	case cvssScore >= 7.0:
		return SevHigh
	case cvssScore >= 4.0:
		return SevMedium
	case cvssScore > 0:
		return SevLow
	default:
		return SevMedium
	}
}

func guessEcosystem(packageName string) string {
	if strings.HasPrefix(packageName, "@") {
		return "npm"
	}
	if strings.Count(packageName, "/") >= 1 {
		return "go"
	}
	return "npm"
}
