package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/mcheviron/mcp-audit/internal/config"
	"github.com/mcheviron/mcp-audit/internal/mcp"
)

var (
	errTooManyRedirects   = errors.New("too many redirects")
	errRedirectToInternal = errors.New("redirect to internal host blocked")
)

type probeResult struct {
	target      string
	status      int
	body        string
	err         error
	redirect    string
	redirectHop int
	contentType string
	duration    time.Duration
}

func probeTargetDirect(
	ctx context.Context, client *http.Client, method, target string,
	depth ProbeDepth, maxResp int64, headers ...string,
) probeResult {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return probeResult{target: target, err: err}
	}
	if len(headers) >= 2 && headers[0] != "" {
		req.Header.Set(headers[0], headers[1])
	}

	resp, err := client.Do(req)
	if err != nil {
		return probeResult{target: target, err: err, duration: time.Since(start)}
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Debug("close response body", "err", err)
		}
	}()

	limited := io.LimitReader(resp.Body, maxResp)
	var buf strings.Builder
	if _, err := io.Copy(&buf, limited); err != nil {
		slog.Debug("copy response body", "err", err)
	}

	result := probeResult{
		target:      target,
		status:      resp.StatusCode,
		body:        buf.String(),
		contentType: resp.Header.Get("Content-Type"),
		duration:    time.Since(start),
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
				return errTooManyRedirects
			}
			if isInternalHost(req.URL.String()) {
				return errRedirectToInternal
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

func runDirectProbes(
	parentCtx context.Context,
	httpServers []config.ServerEntry, targets []string, depth ProbeDepth, maxResp int64,
	concurrency int,
) ([]Result, []probeTiming, error) {
	var results []Result
	var timings []probeTiming
	var mu sync.Mutex

	g, ctx := errgroup.WithContext(parentCtx)
	g.SetLimit(concurrency)
	client := newProbeClient(5*time.Second, depth)

	for _, srv := range httpServers {
		for _, target := range targets {
			srv, target := srv, target
			g.Go(func() error {
				probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				defer cancel()
				for _, method := range probeMethods {
					if method != http.MethodGet && depth < DepthExtended {
						continue
					}
					headerVariants := [][]string{nil}
					if depth >= DepthExtended {
						for hk, hv := range probeHeaders {
							headerVariants = append(headerVariants, []string{hk, hv})
						}
					}
					for _, h := range headerVariants {
						var result probeResult
						if err := retry(probeCtx, 1, func() error {
							result = probeTargetDirect(probeCtx, client, method, target, depth, maxResp, h...)
							return result.err
						}); err != nil {
							slog.Debug("probe retry exhausted", "target", target, "err", err)
						}
						r := analyzeProbeResult(result, srv)
						r.ConfigPath = srv.ConfigPath
						if h != nil {
							r.Finding = fmt.Sprintf("[%s|%s:%s] %s", method, h[0], h[1], r.Finding)
						} else {
							r.Scope = srv.Scope
							if method != http.MethodGet {
								r.Finding = fmt.Sprintf("[%s] %s", method, r.Finding)
							}
							if result.redirectHop > 0 {
								r.Finding = fmt.Sprintf("redirect hop %d to %s: %s", result.redirectHop, result.redirect, r.Finding)
							}
						}
						mu.Lock()
						results = append(results, r)
						if result.duration > 0 {
							timings = append(timings, probeTiming{
								server: srv.Name, duration: result.duration, configPath: srv.ConfigPath,
							})
						}
						mu.Unlock()
					}
				}
				return nil
			})
		}
	}

	if err := g.Wait(); err != nil {
		return results, timings, fmt.Errorf("direct probe group: %w", err)
	}
	return results, timings, nil
}

func runMCPProbes(
	parentCtx context.Context,
	servers []config.ServerEntry, targets []string, transportFlag string, auth AuthConfig,
	toolAnalysis bool, allTools map[string][]mcp.Tool, driftCfg driftConfig,
	depth ProbeDepth, cl *CallbackListener,
	concurrency, timeoutSecs int,
) ([]Result, error) {
	var results []Result
	var mu sync.Mutex

	g, ctx := errgroup.WithContext(parentCtx)
	g.SetLimit(concurrency)

	for _, srv := range servers {
		g.Go(func() error {
			probeCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSecs)*time.Second)
			defer cancel()
			probeSingleServer(probeCtx, srv, &results, &mu, targets,
				transportFlag, auth, toolAnalysis, allTools, driftCfg, depth, cl)
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return results, fmt.Errorf("MCP probe group: %w", err)
	}
	return results, nil
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
	mcpClient, err := handshakeServer(ctx, srv, transportFlag, auth)
	if err != nil {
		addHandshakeError(err, srv, auth, existingResults, mu)
		return
	}
	defer func() {
		if err := mcpClient.Close(); err != nil {
			slog.Debug("close client", "err", err)
		}
	}()

	tools, err := mcpClient.ListTools(ctx)
	if err != nil {
		mu.Lock()
		*existingResults = append(*existingResults, Result{
			Severity:   SevInfo,
			Server:     srv.Name,
			Type:       FindingTypeDynamic,
			Finding:    fmt.Sprintf("tools/list failed: %v", err),
			ConfigPath: srv.ConfigPath,
			Scope:      srv.Scope,
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
			toolResults[i].Scope = srv.Scope
		}
		mu.Lock()
		*existingResults = append(*existingResults, toolResults...)
		mu.Unlock()
	}
}

func (s *Scanner) runProbes(
	ctx context.Context,
	httpServers, mcpServers []config.ServerEntry,
	targets []string,
	depth ProbeDepth,
	concurrency, timeoutSecs int,
	cl *CallbackListener,
) []Result {
	auth := s.authConfig()
	allTools := make(map[string][]mcp.Tool)
	driftCfg := driftConfig{
		snapshotDir:       s.Snapshot.Dir,
		noSnapshot:        s.Snapshot.Disabled,
		noTrustOnFirstUse: s.Snapshot.NoTrustOnFirstUse,
		trustConfig:       s.Trust,
	}
	maxResp := int64(s.Probe.MaxResponseSize)

	var directResults, mcpResults []Result
	var directTimings []probeTiming
	var dirErr, mcpErr error

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		directResults, directTimings, dirErr = runDirectProbes(gctx, httpServers, targets, depth, maxResp, concurrency)
		return dirErr
	})
	g.Go(func() error {
		mcpResults, mcpErr = runMCPProbes(
			gctx, mcpServers, targets, s.Transport, auth, s.ToolAnalysis, allTools, driftCfg, depth, cl,
			concurrency, timeoutSecs,
		)
		return mcpErr
	})
	if err := g.Wait(); err != nil {
		slog.Warn("probe group error (timeout or cancellation)", "err", err)
	}

	var results []Result
	results = append(results, directResults...)
	results = append(results, mcpResults...)
	results = append(results, analyzeTiming(directTimings)...)
	results = s.analyzeCollectedTools(allTools, results)

	s.LastProbeTools = allTools

	return results
}
