package scanner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/mcheviron/mcp-audit/internal/config"
	"github.com/mcheviron/mcp-audit/internal/mcp"
)

func (s *Scanner) collectServers() []config.ServerEntry {
	configs := s.discoverConfigs()
	var servers []config.ServerEntry
	for _, c := range configs {
		servers = append(servers, c.Servers...)
	}
	return servers
}

func addHandshakeError(err error, srv config.ServerEntry, auth AuthConfig, results *[]Result, mu *sync.Mutex) {
	finding := fmt.Sprintf("MCP handshake failed: %v", err)
	if noAuthConfigured(srv, auth) && errors.Is(err, mcp.ErrAuthRequired) {
		finding += " (no auth configured — server returned 401/403)"
	}
	mu.Lock()
	*results = append(*results, Result{
		Severity:   SevInfo,
		Server:     srv.Name,
		Type:       "dynamic",
		Finding:    finding,
		ConfigPath: srv.ConfigPath,
		Scope:      srv.Scope,
	})
	mu.Unlock()
}

func runToolAnalysis(tools *mcp.ListToolsResult, srv config.ServerEntry, results *[]Result, mu *sync.Mutex) {
	var descResults, capResults []Result
	for _, tool := range tools.Tools {
		descResults = append(descResults, analyzeToolDescription(tool, srv.Name, srv.ConfigPath, srv.Scope)...)
		caps := classifyToolCapabilities(tool.InputSchema)
		if len(caps) == 0 {
			continue
		}
		sev := SevInfo
		for _, c := range caps {
			if c == "shell" {
				sev = SevHigh
			}
		}
		capResults = append(capResults, Result{
			Severity:   sev,
			Server:     srv.Name,
			Type:       "static",
			Finding:    fmt.Sprintf("tool %q capabilities: %s", tool.Name, strings.Join(caps, ", ")),
			ConfigPath: srv.ConfigPath,
			Scope:      srv.Scope,
		})
		if len(caps) > 1 {
			capResults = append(capResults, Result{
				Severity:   SevMedium,
				Server:     srv.Name,
				Type:       "static",
				Finding:    fmt.Sprintf("tool %q has multiple capabilities: %s", tool.Name, strings.Join(caps, ", ")),
				ConfigPath: srv.ConfigPath,
				Scope:      srv.Scope,
			})
		}
	}
	mu.Lock()
	*results = append(*results, descResults...)
	*results = append(*results, capResults...)
	mu.Unlock()
}

func (s *Scanner) partitionServers() (httpServers, mcpServers []config.ServerEntry) {
	for _, srv := range s.collectServers() {
		if s.TrustConfig != nil {
			scope := s.TrustConfig.ScopeFor(srv.Name, srv.Tool)
			if len(scope.Blocked) > 0 {
				continue
			}
		}
		if srv.Kind() == config.TransportHTTP {
			httpServers = append(httpServers, srv)
		}
		mcpServers = append(mcpServers, srv)
	}
	return httpServers, mcpServers
}

func (s *Scanner) resolveTargets(depth ProbeDepth) []string {
	if len(s.Probes) > 0 {
		return filterTargets(s.Probes, s.AllowHosts, s.BlockHosts)
	}
	probeURLs := getProbeTargets(depth)
	if s.TargetsFile != "" {
		if loaded := loadTargetsFile(s.TargetsFile); len(loaded) > 0 {
			probeURLs = loaded
		}
	}
	return filterTargets(probeURLs, s.AllowHosts, s.BlockHosts)
}

func dryRunResults(mcpServers []config.ServerEntry, targets []string, depth ProbeDepth) []Result {
	var results []Result
	for _, srv := range mcpServers {
		desc := srv.URL
		if srv.Command != "" {
			desc = srv.Command
		}
		results = append(results, Result{
			Severity:   SevInfo,
			Server:     srv.Name,
			Type:       "dynamic",
			ConfigPath: srv.ConfigPath,
			Scope:      srv.Scope,
			Finding: fmt.Sprintf(
				"would probe %d targets on %s (transport: %s, depth: %s)", len(targets), desc, srv.Transport, depth,
			),
		})
	}
	return results
}

func (s *Scanner) Probe(dryRun bool) []Result {
	httpServers, mcpServers := s.partitionServers()
	depth := s.ProbeDepth
	targets := s.resolveTargets(depth)

	if dryRun {
		return dryRunResults(mcpServers, targets, depth)
	}

	concurrency := s.Concurrency
	if concurrency <= 0 {
		concurrency = 10
	}
	timeoutSecs := s.TimeoutSecs
	if timeoutSecs <= 0 {
		timeoutSecs = 30
	}

	overallTimeout := time.Duration(timeoutSecs*concurrency+30) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), overallTimeout)
	defer cancel()

	cl := s.setupCallbackListener(depth)

	results := s.runProbes(ctx, httpServers, mcpServers, targets, depth, concurrency, timeoutSecs, cl)

	if cl != nil {
		cl.drainCallbacks(30 * time.Second)
		for _, srv := range mcpServers {
			results = append(results, cl.collectCallbackResults(srv.Name, srv.ConfigPath)...)
		}
		cl.stopCallbackListener()
	}

	return results
}

func (s *Scanner) setupCallbackListener(depth ProbeDepth) *CallbackListener {
	if depth < DepthFull {
		return nil
	}
	cl, err := startCallbackListener(s.CallbackPort)
	if err != nil {
		slog.Warn("callback listener could not bind, blind SSRF detection disabled", "err", err)
	}
	return cl
}

func (s *Scanner) analyzeCollectedTools(allTools map[string][]mcp.Tool, results []Result) []Result {
	if s.ToolAnalysis && len(allTools) > 1 {
		shadowResults := detectToolShadowing(allTools)
		results = append(results, shadowResults...)
	}

	if s.CrossServerAnalysis && len(allTools) > 1 {
		crossResults := runCrossServerAnalysis(allTools)
		results = append(results, crossResults...)
	}
	return results
}
