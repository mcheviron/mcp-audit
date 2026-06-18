package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/mostafaelataby-cheviron/mcp-audit/internal/config"
	"github.com/mostafaelataby-cheviron/mcp-audit/internal/mcp"
)

var probeTargets = []string{
	"http://127.0.0.1/",
	"http://127.0.0.1:80/",
	"http://127.0.0.1:8080/",
	"http://127.0.0.1:3000/",
	"http://[::1]/",
	"http://0.0.0.0/",
	"http://169.254.169.254/latest/meta-data/",
	"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
	"http://169.254.169.254/latest/user-data/",
	"http://metadata.google.internal/computeMetadata/v1/",
	"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
	"http://192.168.1.1/",
	"http://10.0.0.1/",
	"http://172.16.0.1/",
}

func filterTargets(targets, allowHosts, blockHosts []string) []string {
	if len(allowHosts) == 0 && len(blockHosts) == 0 {
		return targets
	}

	var filtered []string
	for _, t := range targets {
		if len(blockHosts) > 0 && hostMatchesAny(t, blockHosts) {
			continue
		}
		if len(allowHosts) > 0 && !hostMatchesAny(t, allowHosts) {
			continue
		}
		filtered = append(filtered, t)
	}
	return filtered
}

func hostMatchesAny(target string, hosts []string) bool {
	for _, h := range hosts {
		if strings.Contains(target, h) {
			return true
		}
	}
	return false
}

type probeClient struct {
	httpClient *http.Client
}

func newProbeClient(timeout time.Duration) *probeClient {
	return &probeClient{
		httpClient: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

type probeResult struct {
	target   string
	status   int
	body     string
	err      error
	redirect string
}

func probeTargetDirect(ctx context.Context, client *probeClient, target string) probeResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return probeResult{target: target, err: err}
	}

	resp, err := client.httpClient.Do(req)
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

	return result
}

func (s *Scanner) collectServers() []config.ServerEntry {
	configs := s.discoverConfigs()
	var servers []config.ServerEntry
	for _, c := range configs {
		servers = append(servers, c.Servers...)
	}
	return servers
}

func runDirectProbes(httpServers []config.ServerEntry, targets []string) []Result {
	var results []Result
	var mu sync.Mutex
	client := newProbeClient(5 * time.Second)

	g, ctx := errgroup.WithContext(context.Background())
	g.SetLimit(10)

	for _, srv := range httpServers {
		for _, target := range targets {
			srv, target := srv, target
			g.Go(func() error {
				result := probeTargetDirect(ctx, client, target)
				r := analyzeProbeResult(result, srv)
				r.ConfigPath = srv.ConfigPath
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
				return nil
			})
		}
	}

	_ = g.Wait()
	return results
}

func newTransport(srv config.ServerEntry, forceFlag string, auth AuthConfig) (mcp.Transport, error) {
	kind := srv.Kind()
	if forceFlag != "" {
		switch forceFlag {
		case "stdio":
			kind = config.TransportStdio
		case "http":
			kind = config.TransportHTTP
		case "sse":
			kind = config.TransportSSE
		default:
			return nil, fmt.Errorf("unknown transport flag: %s", forceFlag)
		}
	}

	switch kind {
	case config.TransportStdio:
		if forceFlag == "" {
			return nil, fmt.Errorf(
				"stdio transport requires explicit --transport stdio flag to execute commands from config")
		}
		if srv.Command == "" {
			return nil, fmt.Errorf("no command for stdio transport")
		}
		tr := mcp.NewStdioTransport(srv.Command, srv.Args, mcp.DefaultTimeout)
		if err := applyAuth(tr, srv, auth); err != nil {
			return nil, err
		}
		return tr, nil
	case config.TransportHTTP:
		if srv.URL == "" {
			return nil, fmt.Errorf("no URL for HTTP transport")
		}
		if forceFlag != "" {
			tr := mcp.NewHTTPTransport(srv.URL, mcp.DefaultTimeout)
			if err := applyAuth(tr, srv, auth); err != nil {
				return nil, err
			}
			return tr, nil
		}
		tr := mcp.NewAutoTransport(srv.URL, mcp.DefaultTimeout)
		if err := applyAuth(tr, srv, auth); err != nil {
			return nil, err
		}
		return tr, nil
	case config.TransportSSE:
		if srv.URL == "" {
			return nil, fmt.Errorf("no URL for SSE transport")
		}
		tr := mcp.NewSSETransport(srv.URL, mcp.DefaultTimeout)
		if err := applyAuth(tr, srv, auth); err != nil {
			return nil, err
		}
		return tr, nil
	default:
		return nil, fmt.Errorf("unknown transport: %v", kind)
	}
}

func applyAuth(tr mcp.Transport, srv config.ServerEntry, global AuthConfig) error {
	token := srv.AuthToken
	if token == "" {
		token = global.Token
	}
	if token != "" {
		tr.SetAuthToken(token)
	}

	if len(global.Headers) > 0 || len(srv.AuthHeaders) > 0 {
		headers := make(map[string]string)
		maps.Copy(headers, global.Headers)
		maps.Copy(headers, srv.AuthHeaders)
		tr.SetAuthHeaders(headers)
	}

	certFile := srv.TLSCertFile
	if certFile == "" {
		certFile = global.Cert
	}
	keyFile := srv.TLSKeyFile
	if keyFile == "" {
		keyFile = global.Key
	}
	if certFile != "" && keyFile != "" {
		if err := tr.SetTLS(certFile, keyFile); err != nil {
			return fmt.Errorf("TLS setup failed: %w", err)
		}
	}
	return nil
}

func runMCPProbes(
	servers []config.ServerEntry, existingResults *[]Result, mu *sync.Mutex,
	targets []string, transportFlag string, auth AuthConfig, toolAnalysis bool,
	allTools map[string][]mcp.Tool, driftCfg driftConfig,
) {
	g, ctx := errgroup.WithContext(context.Background())
	g.SetLimit(10)

	for _, srv := range servers {
		g.Go(func() error {
			probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			probeSingleServer(probeCtx, srv, existingResults, mu, targets,
				transportFlag, auth, toolAnalysis, allTools, driftCfg)
			return nil
		})
	}

	_ = g.Wait()
}

func handshakeServer(
	ctx context.Context, srv config.ServerEntry, transportFlag string, auth AuthConfig,
) (mcp.Client, mcp.Transport, error) {
	transport, err := newTransport(srv, transportFlag, auth)
	if err != nil {
		return nil, nil, err
	}

	mcpClient := mcp.NewClient(transport)
	_, err = mcpClient.Initialize(ctx)
	if err != nil {
		_ = transport.Close()
		return nil, nil, err
	}

	return mcpClient, transport, nil
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
		toolResults := probeMCPTool(ctx, mcpClient, srv, tool, targets[:min(len(targets), 3)])
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

func noAuthConfigured(srv config.ServerEntry, global AuthConfig) bool {
	return srv.AuthToken == "" && len(srv.AuthHeaders) == 0 &&
		global.Token == "" && len(global.Headers) == 0 &&
		srv.TLSCertFile == "" && srv.TLSKeyFile == "" &&
		global.Cert == "" && global.Key == ""
}

func (s *Scanner) Probe(dryRun bool) []Result {
	allServers := s.collectServers()

	var httpServers []config.ServerEntry
	var mcpServers []config.ServerEntry
	for _, srv := range allServers {
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

	baseTargets := probeTargets
	if len(s.Probes) > 0 {
		baseTargets = s.Probes
	}
	targets := filterTargets(baseTargets, s.AllowHosts, s.BlockHosts)

	if dryRun {
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
					"would probe %d targets on %s (transport: %s)", len(targets), desc, srv.Transport,
				),
			})
		}
		return results
	}

	results := runDirectProbes(httpServers, targets)

	auth := s.authConfig()

	var mu sync.Mutex
	allTools := make(map[string][]mcp.Tool)
	driftCfg := driftConfig{
		snapshotDir:       s.SnapshotDir,
		noSnapshot:        s.NoSnapshot,
		noTrustOnFirstUse: s.NoTrustOnFirstUse,
		trustConfig:       s.TrustConfig,
	}
	runMCPProbes(mcpServers, &results, &mu, targets, s.Transport, auth, s.ToolAnalysis, allTools, driftCfg)

	if s.ToolAnalysis && len(allTools) > 1 {
		shadowResults := detectToolShadowing(allTools)
		results = append(results, shadowResults...)
	}

	return results
}
