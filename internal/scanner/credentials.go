package scanner

import (
	"fmt"

	"github.com/hashicorp/go-set"
	"github.com/mcheviron/mcp-audit/internal/config"
	"github.com/mcheviron/mcp-audit/internal/secrets"
)

func (s *Scanner) checkCredentials(cfg config.Config) []Result {
	if s.Snapshot.NoSecretScan {
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
		Type:       FindingTypeStatic,
		Finding:    finding,
		ConfigPath: configPath,
	}
}

func dedupCredResults(results []Result) []Result {
	seen := set.New[string](0)
	var out []Result
	for _, r := range results {
		key := r.Finding + "|" + r.ConfigPath
		if seen.Contains(key) {
			continue
		}
		seen.Insert(key)
		out = append(out, r)
	}
	return out
}
