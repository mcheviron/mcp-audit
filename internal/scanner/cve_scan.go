package scanner

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-set"
	"github.com/mcheviron/mcp-audit/internal/config"
)

type serverInfo struct {
	Name       string
	Package    string
	ConfigPath string
	Scope      string
}

var cveSem = make(chan struct{}, 1)

func (s *Scanner) scanCVEs(configs []config.Config) []Result {
	if s.CVE.Disabled {
		return nil
	}

	servers := collectServersFromConfigs(configs)
	if len(servers) == 0 {
		return nil
	}

	if s.CVE.CacheDir != "" {
		_ = os.MkdirAll(s.CVE.CacheDir, 0o700)
	}

	seenPackages := set.New[string](0)
	type pkgWork struct {
		pkg string
		srv serverInfo
	}
	var work []pkgWork
	for _, srv := range servers {
		pkg := strings.TrimSpace(srv.Package)
		if pkg == "" || seenPackages.Contains(pkg) {
			continue
		}
		seenPackages.Insert(pkg)
		work = append(work, pkgWork{pkg: pkg, srv: srv})
	}

	type pkgResult struct {
		srv     serverInfo
		pkg     string
		entries []CVEEntry
	}
	resultsCh := make(chan pkgResult, len(work))
	var wg sync.WaitGroup
	for _, w := range work {
		wg.Add(1)
		go func(w pkgWork) {
			defer wg.Done()
			entries := s.fetchCVEEntries(w.pkg)
			resultsCh <- pkgResult{srv: w.srv, pkg: w.pkg, entries: entries}
		}(w)
	}
	wg.Wait()
	close(resultsCh)

	var results []Result
	for pr := range resultsCh {
		results = append(results, buildCVEResults(pr.srv, pr.pkg, pr.entries)...)
	}
	return results
}

func (s *Scanner) fetchCVEEntries(pkg string) []CVEEntry {
	if cached, ok := loadCVECache(s.CVE.CacheDir, pkg, s.CVE.CacheTTLHrs); ok {
		slog.Debug("cve cache hit", "package", pkg)
		return cached
	}

	cveSem <- struct{}{}
	defer func() { <-cveSem }()
	time.Sleep(cveRateLimitDelay)

	var (
		nvdEntries, ghEntries []CVEEntry
		nvdErr, ghErr         error
	)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		nvdEntries, nvdErr = queryNVD(pkg)
		if nvdErr != nil {
			slog.Warn("NVD query failed", "package", pkg, "error", nvdErr)
		}
	}()
	go func() {
		defer wg.Done()
		ghEntries, ghErr = queryGitHubAdvisory(pkg, guessEcosystem(pkg))
		if ghErr != nil {
			slog.Warn("GitHub Advisory query failed", "package", pkg, "error", ghErr)
		}
	}()
	wg.Wait()

	deduped := deduplicateCVEs(append(nvdEntries, ghEntries...))
	if nvdErr == nil || ghErr == nil {
		if err := writeCVECache(s.CVE.CacheDir, pkg, deduped); err != nil {
			slog.Warn("cve cache write failed", "package", pkg, "error", err)
		}
	}
	return deduped
}

func buildCVEResults(srv serverInfo, pkg string, entries []CVEEntry) []Result {
	var results []Result
	for _, entry := range entries {
		sev := cveSeverity(entry.CVSSScore)
		detail := fmt.Sprintf("%s (CVSS %.1f)", entry.Description, entry.CVSSScore)
		if entry.Published != "" {
			detail += fmt.Sprintf(" | published: %s", entry.Published)
		}
		results = append(results, Result{
			Severity:    sev,
			Server:      srv.Name,
			Package:     pkg,
			Type:        FindingTypeCVE,
			Finding:     fmt.Sprintf("%s: %s", entry.ID, entry.Description),
			Detail:      detail,
			ConfigPath:  srv.ConfigPath,
			Remediation: fmt.Sprintf("Review %s and apply vendor patch. See: %s", entry.ID, entry.URL),
			Scope:       srv.Scope,
		})
	}
	if len(entries) == 0 {
		results = append(results, Result{
			Severity:   SevPass,
			Server:     srv.Name,
			Type:       FindingTypeCVE,
			Finding:    fmt.Sprintf("no known CVEs for package %q", pkg),
			ConfigPath: srv.ConfigPath,
			Scope:      srv.Scope,
		})
	}
	return results
}

func collectServersFromConfigs(configs []config.Config) []serverInfo {
	var servers []serverInfo
	for _, cfg := range configs {
		for _, srv := range cfg.Servers {
			servers = append(servers, serverInfo{
				Name:       srv.Name,
				Package:    srv.Package,
				ConfigPath: srv.ConfigPath,
				Scope:      srv.Scope,
			})
		}
	}
	return servers
}

func deduplicateCVEs(entries []CVEEntry) []CVEEntry {
	seen := set.New[string](0)
	var out []CVEEntry
	for _, e := range entries {
		if !seen.Contains(e.ID) {
			seen.Insert(e.ID)
			out = append(out, e)
		}
	}
	return out
}
