package scanner

import (
	"fmt"
	"strings"

	"github.com/mostafaelataby-cheviron/mcp-audit/internal/config"
	"github.com/mostafaelataby-cheviron/mcp-audit/pkg/levenshtein"
)

type Result struct {
	Severity   Severity
	Server     string
	Type       string
	Finding    string
	Detail     string
	ConfigPath string
}

type Severity int

const (
	SevPass Severity = iota
	SevInfo
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevPass:
		return "PASS"
	case SevInfo:
		return "INFO"
	case SevLow:
		return "LOW"
	case SevMedium:
		return "MEDIUM"
	case SevHigh:
		return "HIGH"
	case SevCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

type StaticResults struct {
	Configs []config.Config
	Results []Result
}

func RunStatic() (*StaticResults, error) {
	configs := config.Discover()

	var results []Result
	for _, cfg := range configs {
		if cfg.Error != nil {
			results = append(results, Result{
				Severity:   SevInfo,
				Server:     cfg.Tool,
				Type:       "static",
				ConfigPath: cfg.Path,
				Finding:    fmt.Sprintf("config parse error: %v", cfg.Error),
			})
			continue
		}
		for _, srv := range cfg.Servers {
			r := checkTyposquat(srv)
			for i := range r {
				r[i].ConfigPath = srv.ConfigPath
			}
			results = append(results, r...)
		}
	}

	return &StaticResults{
		Configs: configs,
		Results: results,
	}, nil
}

func checkTyposquat(srv config.ServerEntry) []Result {
	if srv.Package == "" {
		return []Result{{
			Severity: SevPass,
			Server:   srv.Name,
			Type:     "static",
			Finding:  "no package identifier to check",
		}}
	}

	for _, m := range knownMalicious {
		if strings.EqualFold(srv.Package, m) {
			return []Result{{
				Severity: SevCritical,
				Server:   srv.Name,
				Type:     "static",
				Finding:  fmt.Sprintf("package %q matches known malicious package %q", srv.Package, m),
			}}
		}
	}

	for _, l := range knownLegitimate {
		if strings.EqualFold(srv.Package, l) {
			return []Result{{
				Severity: SevPass,
				Server:   srv.Name,
				Type:     "static",
				Finding:  "known legitimate package",
			}}
		}
	}

	var findings []Result
	for _, l := range knownLegitimate {
		d := levenshtein.Distance(srv.Package, l)
		if d <= 2 && d > 0 {
			findings = append(findings, Result{
				Severity: SevInfo,
				Server:   srv.Name,
				Type:     "static",
				Finding: fmt.Sprintf("potential typosquat: %q is distance %d from known package %q",
					srv.Package, d, l),
			})
		}
	}

	if len(findings) == 0 {
		findings = append(findings, Result{
			Severity: SevPass,
			Server:   srv.Name,
			Type:     "static",
			Finding:  "package not in known lists, no typosquat detected",
		})
	}

	return findings
}
