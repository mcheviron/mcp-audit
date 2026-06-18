package scanner

import (
	"fmt"

	"github.com/mostafaelataby-cheviron/mcp-audit/internal/config"
	"github.com/mostafaelataby-cheviron/mcp-audit/internal/secrets"
)

func (s *Scanner) checkCredentials(cfg config.Config) []Result {
	if s.NoSecretScan {
		return nil
	}
	var results []Result
	for _, f := range secrets.ScanRaw(cfg.Raw, cfg.Path) {
		results = append(results, credResult(cfg.Tool, cfg.Path,
			fmt.Sprintf("%s detected in %s", f.Type, f.Location)))
	}
	for _, srv := range cfg.Servers {
		results = append(results, scanServerCredentials(srv)...)
	}
	return dedupCredResults(results)
}

func scanServerCredentials(srv config.ServerEntry) []Result {
	var results []Result
	creds := append(append(
		secrets.ScanEnv(srv.Env, srv.Name),
		secrets.ScanArgs(srv.Args, srv.Name)...),
		secrets.ScanHeaders(srv.Headers, srv.Name)...)
	for _, f := range creds {
		results = append(results, credResult(srv.Name, srv.ConfigPath,
			fmt.Sprintf("%s in %s", f.Type, f.Location)))
	}
	return results
}

func credResult(server, configPath, finding string) Result {
	return Result{
		Severity:   SevCritical,
		Server:     server,
		Type:       "static",
		Finding:    finding,
		ConfigPath: configPath,
	}
}

func dedupCredResults(results []Result) []Result {
	seen := map[string]bool{}
	var out []Result
	for _, r := range results {
		key := r.Finding + "|" + r.ConfigPath
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, r)
	}
	return out
}
