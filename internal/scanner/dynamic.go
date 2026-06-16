package scanner

import (
	"context"
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

type DynamicConfig struct {
	AllowHosts []string
	BlockHosts []string
	Targets    []string
	DryRun     bool
}

func collectHTTPServers() []config.ServerEntry {
	configs := config.Discover()
	var httpServers []config.ServerEntry
	for _, c := range configs {
		for _, srv := range c.Servers {
			if srv.Transport == "http" {
				httpServers = append(httpServers, srv)
			}
		}
	}
	return httpServers
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

func runMCPProbes(httpServers []config.ServerEntry, existingResults *[]Result, mu *sync.Mutex, targets []string) {
	g, ctx := errgroup.WithContext(context.Background())
	g.SetLimit(10)

	for _, srv := range httpServers {
		g.Go(func() error {
			probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()

			mcpClient := mcp.NewClient(srv.URL, 5*time.Second)
			_, err := mcpClient.Initialize(probeCtx)
			if err != nil {
				mu.Lock()
				*existingResults = append(*existingResults, Result{
					Severity:   SevInfo,
					Server:     srv.Name,
					Type:       "dynamic",
					Finding:    fmt.Sprintf("MCP handshake failed: %v", err),
					ConfigPath: srv.ConfigPath,
				})
				mu.Unlock()
				return nil
			}

			tools, err := mcpClient.ListTools(probeCtx)
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
				return nil
			}

			for _, tool := range tools.Tools {
				toolResults := probeMCPTool(probeCtx, mcpClient, srv, tool, targets[:3])
				for i := range toolResults {
					toolResults[i].ConfigPath = srv.ConfigPath
				}
				mu.Lock()
				*existingResults = append(*existingResults, toolResults...)
				mu.Unlock()
			}

			return nil
		})
	}

	_ = g.Wait()
}

func RunDynamic(cfg DynamicConfig) []Result {
	httpServers := collectHTTPServers()
	baseTargets := probeTargets
	if len(cfg.Targets) > 0 {
		baseTargets = cfg.Targets
	}
	targets := filterTargets(baseTargets, cfg.AllowHosts, cfg.BlockHosts)

	if cfg.DryRun {
		var results []Result
		for _, srv := range httpServers {
			results = append(results, Result{
				Severity:   SevInfo,
				Server:     srv.Name,
				Type:       "dynamic",
				ConfigPath: srv.ConfigPath,
				Finding: fmt.Sprintf(
					"would probe %d targets on %s", len(targets), srv.URL,
				),
			})
		}
		return results
	}

	results := runDirectProbes(httpServers, targets)

	var mu sync.Mutex
	runMCPProbes(httpServers, &results, &mu, targets)

	return results
}
