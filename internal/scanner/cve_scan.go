package scanner

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/mostafaelataby-cheviron/mcp-audit/internal/config"
)

type serverInfo struct {
	Name       string
	Package    string
	ConfigPath string
	Scope      string
}

func (s *Scanner) scanCVEs(configs []config.Config) []Result { //nolint:funlen
	if s.NoCVEScan {
		return nil
	}

	servers := collectServersFromConfigs(configs)
	if len(servers) == 0 {
		return nil
	}

	if s.CVECacheDir != "" {
		_ = os.MkdirAll(s.CVECacheDir, 0o700)
	}

	var results []Result
	seenPackages := map[string]bool{}

	for _, srv := range servers {
		pkg := strings.TrimSpace(srv.Package)
		if pkg == "" || seenPackages[pkg] {
			continue
		}
		seenPackages[pkg] = true

		var allEntries []CVEEntry

		if cached, ok := loadCVECache(s.CVECacheDir, pkg, s.CVECacheTTLHours); ok {
			allEntries = cached
			slog.Debug("cve cache hit", "package", pkg)
		} else {
			eco := guessEcosystem(pkg)
			var atLeastOneOK bool

			nvdEntries, err := queryNVD(pkg)
			if err != nil {
				slog.Warn("NVD query failed", "package", pkg, "error", err)
			} else {
				allEntries = append(allEntries, nvdEntries...)
				atLeastOneOK = true
			}

			time.Sleep(cveRateLimitDelay)

			ghEntries, err := queryGitHubAdvisory(pkg, eco)
			if err != nil {
				slog.Warn("GitHub Advisory query failed", "package", pkg, "error", err)
			} else {
				allEntries = append(allEntries, ghEntries...)
				atLeastOneOK = true
			}

			deduped := deduplicateCVEs(allEntries)

			if atLeastOneOK {
				if err := writeCVECache(s.CVECacheDir, pkg, deduped); err != nil {
					slog.Warn("cve cache write failed", "package", pkg, "error", err)
				}
			}

			allEntries = deduped
		}

		for _, entry := range allEntries {
			sev := cveSeverity(entry.CVSSScore)
			detail := fmt.Sprintf("%s (CVSS %.1f)", entry.Description, entry.CVSSScore)
			if entry.Published != "" {
				detail += fmt.Sprintf(" | published: %s", entry.Published)
			}
			results = append(results, Result{
				Severity:    sev,
				Server:      srv.Name,
				Type:        "cve",
				Finding:     fmt.Sprintf("%s: %s", entry.ID, entry.Description),
				Detail:      detail,
				ConfigPath:  srv.ConfigPath,
				Remediation: fmt.Sprintf("Review %s and apply vendor patch. See: %s", entry.ID, entry.URL),
				Scope:       srv.Scope,
			})
		}

		if len(allEntries) == 0 {
			results = append(results, Result{
				Severity:   SevPass,
				Server:     srv.Name,
				Type:       "cve",
				Finding:    fmt.Sprintf("no known CVEs for package %q", pkg),
				ConfigPath: srv.ConfigPath,
				Scope:      srv.Scope,
			})
		}
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
	seen := map[string]bool{}
	var out []CVEEntry
	for _, e := range entries {
		if !seen[e.ID] {
			seen[e.ID] = true
			out = append(out, e)
		}
	}
	return out
}
