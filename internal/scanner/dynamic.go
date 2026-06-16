package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
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

var awsKeyPattern = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
var gcpTokenPattern = regexp.MustCompile(`(?i)"access_token"\s*:\s*"ya29\.`)

var metadataPattern = regexp.MustCompile(
	`(?i)(ami-id|instance-id|public-keys|security-groups|service-accounts|access_token|privateKey)`,
)

var internalBodyPattern = regexp.MustCompile(
	`(?i)(internal|admin|localhost|127\.0\.0\.1|192\.168\.|10\.\d+\.|172\.(1[6-9]|2\d|3[01])\.)`,
)

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

func analyzeProbeResult(result probeResult, srv config.ServerEntry) Result {
	if result.err != nil {
		return Result{
			Severity: SevMedium,
			Server:   srv.Name,
			Type:     "dynamic",
			Finding:  fmt.Sprintf("connection to %s failed: %v", result.target, result.err),
		}
	}

	if result.redirect != "" {
		sev := SevHigh
		if result.body == "" && result.status >= 300 {
			sev = SevLow
		}
		return Result{
			Severity: sev,
			Server:   srv.Name,
			Type:     "dynamic",
			Finding:  fmt.Sprintf("open redirect to %s (status %d)", result.redirect, result.status),
		}
	}

	if result.status >= 200 && result.status < 300 {
		if r := checkCriticalPatterns(result, srv); r != nil {
			return *r
		}
	}

	return passResult(srv, result)
}

func checkCriticalPatterns(result probeResult, srv config.ServerEntry) *Result {
	if awsKeyPattern.MatchString(result.body) {
		return &Result{
			Severity: SevCritical,
			Server:   srv.Name,
			Type:     "dynamic",
			Finding:  fmt.Sprintf("AWS credentials exposed via %s", result.target),
			Detail:   sanitizeDetail(result.body),
		}
	}

	if gcpTokenPattern.MatchString(result.body) {
		return &Result{
			Severity: SevCritical,
			Server:   srv.Name,
			Type:     "dynamic",
			Finding:  fmt.Sprintf("GCP access token exposed via %s", result.target),
			Detail:   sanitizeDetail(result.body),
		}
	}

	if metadataPattern.MatchString(result.body) {
		return &Result{
			Severity: SevCritical,
			Server:   srv.Name,
			Type:     "dynamic",
			Finding:  fmt.Sprintf("cloud metadata exposed via %s", result.target),
			Detail:   sanitizeDetail(result.body),
		}
	}

	if internalBodyPattern.MatchString(result.body) {
		return &Result{
			Severity: SevHigh,
			Server:   srv.Name,
			Type:     "dynamic",
			Finding: fmt.Sprintf(
				"internal content returned via %s (status %d, %d bytes)",
				result.target, result.status, len(result.body),
			),
		}
	}

	return nil
}

func passResult(srv config.ServerEntry, result probeResult) Result {
	return Result{
		Severity: SevPass,
		Server:   srv.Name,
		Type:     "dynamic",
		Finding:  fmt.Sprintf("no SSRF detected for %s (status %d)", result.target, result.status),
	}
}

func sanitizeDetail(body string) string {
	if len(body) > 200 {
		return body[:200] + "..."
	}
	return body
}

func probeMCPTool(
	ctx context.Context,
	mcpClient *mcp.Client,
	srv config.ServerEntry,
	tool mcp.Tool,
	targets []string,
) []Result {
	var results []Result

	for _, target := range targets {
		args := buildProbeArgs(tool, target)
		callResult, err := mcpClient.CallTool(ctx, tool.Name, args)
		if err != nil {
			results = append(results, Result{
				Severity: SevMedium,
				Server:   srv.Name,
				Type:     "dynamic",
				Finding:  fmt.Sprintf("tool %q probe to %s failed: %v", tool.Name, target, err),
			})
			continue
		}

		results = append(results, analyzeCallToolResponse(callResult, srv, tool.Name, target))
	}

	return results
}

func buildProbeArgs(tool mcp.Tool, target string) map[string]any {
	schema := tool.InputSchema
	props, _ := schema["properties"].(map[string]any)

	args := map[string]any{}

	if urlKeys := findURLKeys(props); len(urlKeys) > 0 {
		args[urlKeys[0]] = target
		return args
	}

	for key, val := range props {
		propMap, ok := val.(map[string]any)
		if !ok {
			continue
		}
		propType, _ := propMap["type"].(string)
		switch propType {
		case "string":
			args[key] = target
		case "number":
			args[key] = float64(80)
		case "integer":
			args[key] = float64(80)
		case "boolean":
			args[key] = true
		}
		if len(args) > 0 {
			break
		}
	}

	if len(args) == 0 {
		args["url"] = target
	}

	return args
}

func isURLKey(key string, desc string) bool {
	lowKey := strings.ToLower(key)
	lowDesc := strings.ToLower(desc)
	urlTerms := []string{"url", "uri", "fetch", "endpoint", "href"}
	for _, term := range urlTerms {
		if strings.Contains(lowKey, term) || strings.Contains(lowDesc, term) {
			return true
		}
	}
	return false
}

func findURLKeys(props map[string]any) []string {
	var keys []string
	for key, val := range props {
		propMap, ok := val.(map[string]any)
		if !ok {
			continue
		}
		desc, _ := propMap["description"].(string)
		if isURLKey(key, desc) {
			keys = append(keys, key)
		}
	}
	return keys
}

func analyzeCallToolResponse(
	callResult *mcp.CallToolResult,
	srv config.ServerEntry,
	toolName string,
	target string,
) Result {
	if callResult.IsError {
		return Result{
			Severity: SevPass,
			Server:   srv.Name,
			Type:     "dynamic",
			Finding:  fmt.Sprintf("tool %q rejected probe to %s (isError=true)", toolName, target),
		}
	}

	for _, content := range callResult.Content {
		if content.Type != "text" {
			continue
		}

		text := content.Text

		if metadataPattern.MatchString(text) {
			return Result{
				Severity: SevCritical,
				Server:   srv.Name,
				Type:     "dynamic",
				Finding:  fmt.Sprintf("tool %q leaked metadata via probe to %s", toolName, target),
				Detail:   sanitizeDetail(text),
			}
		}

		if awsKeyPattern.MatchString(text) {
			return Result{
				Severity: SevCritical,
				Server:   srv.Name,
				Type:     "dynamic",
				Finding:  fmt.Sprintf("tool %q returned AWS credentials via probe to %s", toolName, target),
				Detail:   sanitizeDetail(text),
			}
		}

		if internalBodyPattern.MatchString(text) {
			return Result{
				Severity: SevHigh,
				Server:   srv.Name,
				Type:     "dynamic",
				Finding:  fmt.Sprintf("tool %q returned internal content via probe to %s", toolName, target),
				Detail:   sanitizeDetail(text),
			}
		}
	}

	return Result{
		Severity: SevPass,
		Server:   srv.Name,
		Type:     "dynamic",
		Finding:  fmt.Sprintf("tool %q handled probe to %s without leaking data", toolName, target),
	}
}

type DynamicConfig struct {
	AllowHosts []string
	BlockHosts []string
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

func runDirectProbes(httpServers []config.ServerEntry) []Result {
	var results []Result
	client := newProbeClient(5 * time.Second)

	for _, srv := range httpServers {
		for _, target := range probeTargets {
			result := probeTargetDirect(context.Background(), client, target)
			results = append(results, analyzeProbeResult(result, srv))
		}
	}
	return results
}

func runMCPProbes(httpServers []config.ServerEntry, existingResults *[]Result, mu *sync.Mutex) {
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
					Severity: SevInfo,
					Server:   srv.Name,
					Type:     "dynamic",
					Finding:  fmt.Sprintf("MCP handshake failed: %v", err),
				})
				mu.Unlock()
				return nil
			}

			tools, err := mcpClient.ListTools(probeCtx)
			if err != nil {
				mu.Lock()
				*existingResults = append(*existingResults, Result{
					Severity: SevInfo,
					Server:   srv.Name,
					Type:     "dynamic",
					Finding:  fmt.Sprintf("tools/list failed: %v", err),
				})
				mu.Unlock()
				return nil
			}

			for _, tool := range tools.Tools {
				toolResults := probeMCPTool(probeCtx, mcpClient, srv, tool, probeTargets[:3])
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

	if cfg.DryRun {
		var results []Result
		for _, srv := range httpServers {
			results = append(results, Result{
				Severity: SevInfo,
				Server:   srv.Name,
				Type:     "dynamic",
				Finding: fmt.Sprintf(
					"would probe %d targets on %s", len(probeTargets), srv.URL,
				),
			})
		}
		return results
	}

	results := runDirectProbes(httpServers)

	var mu sync.Mutex
	runMCPProbes(httpServers, &results, &mu)

	return results
}
