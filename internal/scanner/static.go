package scanner

import (
	"fmt"
	"strings"

	"github.com/mcheviron/mcp-audit/internal/config"
	"github.com/mcheviron/mcp-audit/internal/types"
	"github.com/mcheviron/mcp-audit/pkg/levenshtein"
)

type FindingRef struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Label string `json:"label"`
}

type Result struct {
	Severity    Severity
	Server      string
	Package     string
	Type        string
	Finding     string
	Detail      string
	ConfigPath  string
	Remediation string
	Scope       string
	Score       float64
	RiskScore   float64
	Factors     RiskFactors

	RelatedFindings []FindingRef
	Compliance      []ComplianceTag
}

type ComplianceTag struct {
	Framework string `json:"framework"`
	Control   string `json:"control"`
}

type Severity = types.Severity

const (
	SevPass     = types.SevPass
	SevInfo     = types.SevInfo
	SevLow      = types.SevLow
	SevMedium   = types.SevMedium
	SevHigh     = types.SevHigh
	SevCritical = types.SevCritical
)

func ParseSeverity(s string) Severity {
	v, _ := types.ParseSeverity(s)
	return v
}

type StaticResults struct {
	Configs []config.Config
	Results []Result
}

func (s *Scanner) Static() (*StaticResults, error) {
	configs := s.discoverConfigs()

	var results []Result
	for _, cfg := range configs {
		creds := s.checkCredentials(cfg)
		for i := range creds {
			creds[i].Scope = cfg.Scope
		}
		results = append(results, creds...)
		if cfg.Error != nil {
			results = append(results, Result{
				Severity:   SevInfo,
				Server:     cfg.Tool,
				Type:       "static",
				ConfigPath: cfg.Path,
				Scope:      cfg.Scope,
				Finding:    fmt.Sprintf("config parse error: %v", cfg.Error),
			})
			continue
		}
		for _, srv := range cfg.Servers {
			r := checkTyposquat(srv, s.Trust)
			for i := range r {
				r[i].ConfigPath = srv.ConfigPath
				r[i].Scope = srv.Scope
			}
			results = append(results, r...)
		}
	}

	cveResults := s.scanCVEs(configs)
	results = append(results, cveResults...)

	return &StaticResults{
		Configs: configs,
		Results: results,
	}, nil
}

func checkTyposquat(srv config.ServerEntry, tc *config.TrustConfig) []Result {
	if srv.Package == "" {
		return []Result{{
			Severity: SevPass,
			Server:   srv.Name,
			Type:     "static",
			Finding:  "no package identifier to check",
		}}
	}

	if tc == nil {
		return []Result{{
			Severity: SevPass,
			Server:   srv.Name,
			Type:     "static",
			Finding:  "no trust config loaded",
		}}
	}

	scope := tc.ScopeFor(srv.Name, srv.Tool)

	if len(scope.Trusted) == 0 && len(scope.Blocked) == 0 {
		return []Result{{
			Severity: SevPass,
			Server:   srv.Name,
			Type:     "static",
			Finding:  "no trust rules apply for this package",
		}}
	}

	if r, ok := matchBlocked(srv.Package, scope.Blocked, srv.Name); ok {
		return []Result{r}
	}

	var findings []Result
	for _, l := range scope.Trusted {
		if strings.EqualFold(srv.Package, l) {
			return []Result{{
				Severity: SevPass,
				Server:   srv.Name,
				Type:     "static",
				Finding:  "known trusted package",
			}}
		}
		d := levenshtein.Distance(srv.Package, l)
		if d <= 2 && d > 0 {
			findings = append(findings, Result{
				Severity: SevInfo,
				Server:   srv.Name,
				Type:     "static",
				Finding: fmt.Sprintf("potential typosquat: %q is distance %d from trusted package %q",
					srv.Package, d, l),
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, Result{
			Severity: SevPass,
			Server:   srv.Name,
			Type:     "static",
			Finding:  "package not in trust lists, no typosquat detected",
		})
	}

	return findings
}

func matchBlocked(pkg string, blocked []string, server string) (Result, bool) {
	for _, m := range blocked {
		if strings.EqualFold(pkg, m) {
			return Result{
				Severity: SevCritical,
				Server:   server,
				Type:     "static",
				Finding:  fmt.Sprintf("package %q matches blocked package %q", pkg, m),
			}, true
		}
	}
	return Result{}, false
}
