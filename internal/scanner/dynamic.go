package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/mostafaelataby-cheviron/mcp-audit/internal/config"
	"github.com/mostafaelataby-cheviron/mcp-audit/internal/mcp"
)

type probeResult struct {
	target      string
	status      int
	body        string
	err         error
	redirect    string
	redirectHop int
}

func probeTargetDirect(ctx context.Context, method, target string, depth ProbeDepth, headers ...string) probeResult {
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return probeResult{target: target, err: err}
	}
	if len(headers) >= 2 && headers[0] != "" {
		req.Header.Set(headers[0], headers[1])
	}

	client := newProbeClient(5*time.Second, depth)
	resp, err := client.Do(req)
	if err != nil {
		return probeResult{target: target, err: err}
	}
	defer func() { _ = resp.Body.Close() }()

	limited := io.LimitReader(resp.Body, 4096)
	var buf strings.Builder
	_, _ = io.Copy(&buf, limited)

	result := probeResult{
		target: target,
		status: resp.StatusCode,
		body:   buf.String(),
	}

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if loc := resp.Header.Get("Location"); loc != "" {
			result.redirect = loc
		}
	}

	if depth >= DepthExtended {
		hop, finalURL := countRedirectHops(resp)
		if hop > 0 {
			result.redirectHop = hop
			if finalURL != "" && isInternalHost(finalURL) {
				result.redirect = finalURL
			}
		}
	}

	return result
}

func newProbeClient(timeout time.Duration, depth ProbeDepth) *http.Client {
	client := &http.Client{Timeout: timeout}
	if depth >= DepthExtended {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if isInternalHost(req.URL.String()) {
				return errors.New("redirect to internal host blocked")
			}
			return nil
		}
	} else {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return client
}

func (s *Scanner) collectServers() []config.ServerEntry {
	configs := s.discoverConfigs()
	var servers []config.ServerEntry
	for _, c := range configs {
		servers = append(servers, c.Servers...)
	}
	return servers
}

func runDirectProbes(httpServers []config.ServerEntry, targets []string, depth ProbeDepth) []Result {
	var results []Result
	var mu sync.Mutex

	g, ctx := errgroup.WithContext(context.Background())
	g.SetLimit(10)

	for _, srv := range httpServers {
		for _, target := range targets {
			srv, target := srv, target
			g.Go(func() error {
				for _, method := range probeMethods {
					if method != http.MethodGet && depth < DepthExtended {
						continue
					}
					if depth >= DepthExtended {
						for hk, hv := range probeHeaders {
							result := probeTargetDirect(ctx, method, target, depth, hk, hv)
							r := analyzeProbeResult(result, srv)
							r.ConfigPath = srv.ConfigPath
							r.Finding = fmt.Sprintf("[%s|%s:%s] %s", method, hk, hv, r.Finding)
							mu.Lock()
							results = append(results, r)
							mu.Unlock()
						}
					}
					result := probeTargetDirect(ctx, method, target, depth)
					r := analyzeProbeResult(result, srv)
					r.ConfigPath = srv.ConfigPath
					if method != http.MethodGet {
						r.Finding = fmt.Sprintf("[%s] %s", method, r.Finding)
					}
					if result.redirectHop > 0 {
						r.Finding = fmt.Sprintf("redirect hop %d to %s: %s", result.redirectHop, result.redirect, r.Finding)
					}
					mu.Lock()
					results = append(results, r)
					mu.Unlock()
				}
				return nil
			})
		}
	}

	_ = g.Wait()
	return results
}

func runMCPProbes(
	servers []config.ServerEntry, targets []string, transportFlag string, auth AuthConfig,
	toolAnalysis bool, allTools map[string][]mcp.Tool, driftCfg driftConfig,
	depth ProbeDepth, cl *CallbackListener,
) []Result {
	var results []Result
	var mu sync.Mutex

	g, ctx := errgroup.WithContext(context.Background())
	g.SetLimit(10)

	for _, srv := range servers {
		g.Go(func() error {
			probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			probeSingleServer(probeCtx, srv, &results, &mu, targets,
				transportFlag, auth, toolAnalysis, allTools, driftCfg, depth, cl)
			return nil
		})
	}

	_ = g.Wait()
	return results
}

func probeSingleServer(
	ctx context.Context,
	srv config.ServerEntry,
	existingResults *[]Result,
	mu *sync.Mutex,
	targets []string,
	transportFlag string,
	auth AuthConfig,
	toolAnalysis bool,
	allTools map[string][]mcp.Tool,
	driftCfg driftConfig,
	depth ProbeDepth,
	cl *CallbackListener,
) {
	mcpClient, transport, err := handshakeServer(ctx, srv, transportFlag, auth)
	if err != nil {
		finding := fmt.Sprintf("MCP handshake failed: %v", err)
		if noAuthConfigured(srv, auth) && errors.Is(err, mcp.ErrAuthRequired) {
			finding += " (no auth configured — server returned 401/403)"
		}
		mu.Lock()
		*existingResults = append(*existingResults, Result{
			Severity:   SevInfo,
			Server:     srv.Name,
			Type:       "dynamic",
			Finding:    finding,
			ConfigPath: srv.ConfigPath,
		})
		mu.Unlock()
		return
	}
	defer func() { _ = transport.Close() }()

	tools, err := mcpClient.ListTools(ctx)
	if err != nil {
		mu.Lock()
		*existingResults = append(*existingResults, Result{
			Severity:   SevInfo,
			Server:     srv.Name,
			Type:       "dynamic",
			Finding:    fmt.Sprintf("tools/list failed: %v", err),
			ConfigPath: srv.ConfigPath,
		})
		mu.Unlock()
		return
	}

	if !driftCfg.noSnapshot {
		performDriftCheck(srv, tools.Tools, driftCfg, existingResults, mu)
	}

	if allTools != nil {
		mu.Lock()
		allTools[srv.Name] = tools.Tools
		mu.Unlock()
	}
	if toolAnalysis {
		runToolAnalysis(tools, srv, existingResults, mu)
	}

	for _, tool := range tools.Tools {
		limit := min(len(targets), 3)
		toolResults := probeMCPTool(ctx, mcpClient, srv, tool, targets[:limit], depth, cl)
		for i := range toolResults {
			toolResults[i].ConfigPath = srv.ConfigPath
		}
		mu.Lock()
		*existingResults = append(*existingResults, toolResults...)
		mu.Unlock()
	}
}

func runToolAnalysis(tools *mcp.ListToolsResult, srv config.ServerEntry, results *[]Result, mu *sync.Mutex) {
	var descResults, capResults []Result
	for _, tool := range tools.Tools {
		descResults = append(descResults, analyzeToolDescription(tool, srv.Name, srv.ConfigPath)...)
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
		})
		if len(caps) > 1 {
			capResults = append(capResults, Result{
				Severity:   SevMedium,
				Server:     srv.Name,
				Type:       "static",
				Finding:    fmt.Sprintf("tool %q has multiple capabilities: %s", tool.Name, strings.Join(caps, ", ")),
				ConfigPath: srv.ConfigPath,
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

	var cl *CallbackListener
	if depth >= DepthFull {
		cl = startCallbackListener(s.CallbackPort)
	}

	auth := s.authConfig()
	allTools := make(map[string][]mcp.Tool)
	driftCfg := driftConfig{
		snapshotDir:       s.SnapshotDir,
		noSnapshot:        s.NoSnapshot,
		noTrustOnFirstUse: s.NoTrustOnFirstUse,
		trustConfig:       s.TrustConfig,
	}

	var directResults, mcpResults []Result
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		directResults = runDirectProbes(httpServers, targets, depth)
	}()
	go func() {
		defer wg.Done()
		mcpResults = runMCPProbes(mcpServers, targets, s.Transport, auth, s.ToolAnalysis, allTools, driftCfg, depth, cl)
	}()
	wg.Wait()

	var results []Result
	results = append(results, directResults...)
	results = append(results, mcpResults...)

	if cl != nil {
		cl.drainCallbacks(30 * time.Second)
		for _, srv := range mcpServers {
			results = append(results, cl.collectCallbackResults(srv.Name, srv.ConfigPath)...)
		}
		cl.stopCallbackListener()
	}

	if s.ToolAnalysis && len(allTools) > 1 {
		shadowResults := detectToolShadowing(allTools)
		results = append(results, shadowResults...)
	}

	return results
}
