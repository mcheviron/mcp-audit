package scanner

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestQueryNVD(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := nvdResponse{
			Vulnerabilities: []struct {
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
			}{
				{
					CVE: struct {
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
					}{
						ID: "CVE-2023-12345",
						Description: struct {
							Descriptions []struct {
								Lang  string `json:"lang"`
								Value string `json:"value"`
							} `json:"descriptions"`
						}{
							Descriptions: []struct {
								Lang  string `json:"lang"`
								Value string `json:"value"`
							}{
								{Lang: "en", Value: "Test vulnerability"},
							},
						},
						Metrics: struct {
							CVSSv31 []struct {
								BaseScore float64 `json:"baseScore"`
							} `json:"cvssMetricV31"`
							CVSSv30 []struct {
								BaseScore float64 `json:"baseScore"`
							} `json:"cvssMetricV30"`
							CVSSv20 []struct {
								BaseScore float64 `json:"baseScore"`
							} `json:"cvssMetricV2"`
						}{
							CVSSv31: []struct {
								BaseScore float64 `json:"baseScore"`
							}{{BaseScore: 9.8}},
						},
						Published: "2023-01-15T00:00:00.000Z",
					},
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	origClient := cveHTTPClient
	origURL := nvdBaseURL
	cveHTTPClient = &http.Client{}
	nvdBaseURL = srv.URL
	defer func() {
		cveHTTPClient = origClient
		nvdBaseURL = origURL
	}()

	entries, err := queryNVD("test-package")
	if err != nil {
		t.Fatalf("queryNVD failed: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].ID != "CVE-2023-12345" {
		t.Errorf("expected CVE-2023-12345, got %s", entries[0].ID)
	}
	if entries[0].CVSSScore != 9.8 {
		t.Errorf("expected CVSS 9.8, got %.1f", entries[0].CVSSScore)
	}
}

func TestQueryGitHubAdvisory(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "bad method", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("User-Agent") == "" {
			http.Error(w, "missing User-Agent", http.StatusBadRequest)
			return
		}
		resp := ghAdvisoryResponse{
			{CVEID: "CVE-2024-67890", Summary: "GH advisory test", CVSSScore: 7.5, PublishedAt: "2024-06-01T00:00:00Z", HTMLURL: "https://github.com/advisories/GHSA-xxxx"},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	origClient := cveHTTPClient
	origURL := ghAdvisoryBaseURL
	cveHTTPClient = &http.Client{}
	ghAdvisoryBaseURL = srv.URL
	defer func() {
		cveHTTPClient = origClient
		ghAdvisoryBaseURL = origURL
	}()

	entries, err := queryGitHubAdvisory("test-package", "npm")
	if err != nil {
		t.Fatalf("queryGitHubAdvisory failed: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].ID != "CVE-2024-67890" {
		t.Errorf("expected CVE-2024-67890, got %s", entries[0].ID)
	}
}

func TestCVESeverityMapping(t *testing.T) {
	tests := []struct {
		score    float64
		expected Severity
	}{
		{9.0, SevCritical},
		{8.9, SevHigh},
		{7.0, SevHigh},
		{6.9, SevMedium},
		{4.0, SevMedium},
		{3.9, SevLow},
		{0.1, SevLow},
		{0.0, SevMedium},
	}
	for _, tc := range tests {
		got := cveSeverity(tc.score)
		if got != tc.expected {
			t.Errorf("cveSeverity(%.1f) = %s, want %s", tc.score, got, tc.expected)
		}
	}
}

func TestCVECacheKey(t *testing.T) {
	key1 := cveCacheKey("test-package")
	key2 := cveCacheKey("test-package")
	key3 := cveCacheKey("different-package")
	if key1 != key2 {
		t.Errorf("same input should produce same key: %s != %s", key1, key2)
	}
	if key1 == key3 {
		t.Error("different inputs should produce different keys")
	}
}

func TestCVECacheHit(t *testing.T) {
	tmpDir := t.TempDir()
	pkg := "test-package"
	entries := []CVEEntry{
		{ID: "CVE-2023-11111", CVSSScore: 5.0},
	}
	if err := writeCVECache(tmpDir, pkg, entries); err != nil {
		t.Fatalf("writeCVECache failed: %v", err)
	}

	cached, ok := loadCVECache(tmpDir, pkg, 24)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if len(cached) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(cached))
	}
	if cached[0].ID != "CVE-2023-11111" {
		t.Errorf("expected CVE-2023-11111, got %s", cached[0].ID)
	}
}

func TestCVECacheMiss(t *testing.T) {
	tmpDir := t.TempDir()
	_, ok := loadCVECache(tmpDir, "nonexistent", 24)
	if ok {
		t.Error("expected cache miss for nonexistent key")
	}
}

func TestCVECacheDirCreation(t *testing.T) {
	tmpDir := filepath.Join(t.TempDir(), "new-subdir")
	entries := []CVEEntry{
		{ID: "CVE-2023-22222", CVSSScore: 6.5},
	}
	if err := writeCVECache(tmpDir, "pkg", entries); err != nil {
		t.Fatalf("writeCVECache should create dir: %v", err)
	}
	_, err := os.Stat(tmpDir)
	if err != nil {
		t.Errorf("directory not created: %v", err)
	}
}

func TestGuessEcosystem(t *testing.T) {
	tests := []struct {
		pkg string
		eco string
	}{
		{"@scope/server", "npm"},
		{"github.com/foo/bar", "go"},
		{"simple-package", "npm"},
		{"example.com/module", "go"},
	}
	for _, tc := range tests {
		got := guessEcosystem(tc.pkg)
		if got != tc.eco {
			t.Errorf("guessEcosystem(%q) = %q, want %q", tc.pkg, got, tc.eco)
		}
	}
}

func TestDeduplicateCVEs(t *testing.T) {
	entries := []CVEEntry{
		{ID: "CVE-1", CVSSScore: 5.0},
		{ID: "CVE-2", CVSSScore: 7.0},
		{ID: "CVE-1", CVSSScore: 5.0},
	}
	deduped := deduplicateCVEs(entries)
	if len(deduped) != 2 {
		t.Errorf("expected 2 deduped entries, got %d", len(deduped))
	}
}

func TestQueryNVDEmptyPackage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := nvdResponse{}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	origClient := cveHTTPClient
	origURL := nvdBaseURL
	cveHTTPClient = &http.Client{}
	nvdBaseURL = srv.URL
	defer func() {
		cveHTTPClient = origClient
		nvdBaseURL = origURL
	}()

	entries, err := queryNVD("unlikely-package-name-xyz")
	if err != nil {
		t.Fatalf("queryNVD failed: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for empty result, got %d", len(entries))
	}
}

func TestQueryGitHubAdvisoryRateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("User-Agent", "mcp-audit/test")
		if r.Header.Get("User-Agent") == "" {
			http.Error(w, "missing User-Agent", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	origClient := cveHTTPClient
	origURL := ghAdvisoryBaseURL
	cveHTTPClient = &http.Client{}
	ghAdvisoryBaseURL = srv.URL
	defer func() {
		cveHTTPClient = origClient
		ghAdvisoryBaseURL = origURL
	}()

	_, err := queryGitHubAdvisory("test-pkg", "npm")
	if err == nil {
		t.Error("expected error for rate limit response")
	}
	if !strings.Contains(err.Error(), "rate limited") {
		t.Errorf("expected rate limit error, got: %v", err)
	}
}
