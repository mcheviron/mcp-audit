package scanner

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/mostafaelataby-cheviron/mcp-audit/internal/config"
	"github.com/mostafaelataby-cheviron/mcp-audit/internal/mcp"
)

var awsKeyPattern = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
var gcpTokenPattern = regexp.MustCompile(`(?i)"access_token"\s*:\s*"ya29\.`)

var metadataPattern = regexp.MustCompile(
	`(?i)(ami-id|instance-id|public-keys|security-groups|service-accounts|access_token|privateKey)`,
)

var internalBodyPattern = regexp.MustCompile(
	`(?i)(internal|admin|localhost|127\.0\.0\.1|192\.168\.|10\.\d+\.|172\.(1[6-9]|2\d|3[01])\.)`,
)

var redactPatterns = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`(?i)ya29\.[0-9a-z_-]+`),
	regexp.MustCompile(`(?i)"access_token"\s*:\s*"[^"]+"`),
	regexp.MustCompile(`(?i)"privateKey"\s*:\s*"[^"]+"`),
	regexp.MustCompile(`(?i)-----BEGIN (RSA |EC )?PRIVATE KEY-----[\s\S]*?-----END (RSA |EC )?PRIVATE KEY-----`),
}

func redactDetail(body string) string {
	for _, p := range redactPatterns {
		body = p.ReplaceAllString(body, "[REDACTED]")
	}
	if len(body) > 200 {
		return body[:200] + "..."
	}
	return body
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
			Detail:   redactDetail(result.body),
		}
	}

	if gcpTokenPattern.MatchString(result.body) {
		return &Result{
			Severity: SevCritical,
			Server:   srv.Name,
			Type:     "dynamic",
			Finding:  fmt.Sprintf("GCP access token exposed via %s", result.target),
			Detail:   redactDetail(result.body),
		}
	}

	if metadataPattern.MatchString(result.body) {
		return &Result{
			Severity: SevCritical,
			Server:   srv.Name,
			Type:     "dynamic",
			Finding:  fmt.Sprintf("cloud metadata exposed via %s", result.target),
			Detail:   redactDetail(result.body),
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

	var worst Result
	worst.Severity = SevPass
	worst.Server = srv.Name
	worst.Type = "dynamic"

	for _, content := range callResult.Content {
		if content.Type != "text" {
			continue
		}
		evalToolTextBlock(content.Text, toolName, target, &worst)
	}

	if worst.Severity == SevPass {
		worst.Finding = fmt.Sprintf("tool %q handled probe to %s without leaking data", toolName, target)
	}

	return worst
}

func evalToolTextBlock(text, toolName, target string, worst *Result) {
	if metadataPattern.MatchString(text) && worst.Severity < SevCritical {
		*worst = Result{
			Severity: SevCritical,
			Server:   worst.Server,
			Type:     "dynamic",
			Finding:  fmt.Sprintf("tool %q leaked metadata via probe to %s", toolName, target),
			Detail:   redactDetail(text),
		}
	}

	if awsKeyPattern.MatchString(text) && worst.Severity < SevCritical {
		*worst = Result{
			Severity: SevCritical,
			Server:   worst.Server,
			Type:     "dynamic",
			Finding:  fmt.Sprintf("tool %q returned AWS credentials via probe to %s", toolName, target),
			Detail:   redactDetail(text),
		}
	}

	if gcpTokenPattern.MatchString(text) && worst.Severity < SevCritical {
		*worst = Result{
			Severity: SevCritical,
			Server:   worst.Server,
			Type:     "dynamic",
			Finding:  fmt.Sprintf("tool %q returned GCP token via probe to %s", toolName, target),
			Detail:   redactDetail(text),
		}
	}

	if internalBodyPattern.MatchString(text) && worst.Severity < SevHigh {
		*worst = Result{
			Severity: SevHigh,
			Server:   worst.Server,
			Type:     "dynamic",
			Finding:  fmt.Sprintf("tool %q returned internal content via probe to %s", toolName, target),
			Detail:   redactDetail(text),
		}
	}

	for i, p := range promptInjectionPatterns {
		if m := p.FindString(text); m != "" {
			if worst.Severity < SevHigh {
				*worst = Result{
					Severity: SevHigh,
					Server:   worst.Server,
					Type:     "dynamic",
					Finding: fmt.Sprintf(
						"tool %q response contains prompt injection pattern %q (pattern #%d)",
						toolName, m, i+1),
					Detail: redactDetail(text),
				}
			}
			return
		}
	}
}

func buildProbeArgs(tool mcp.Tool, target string, callbackURL string) map[string]any {
	schema := tool.InputSchema
	props, _ := schema["properties"].(map[string]any)

	args := map[string]any{}

	urlKeys := findURLKeys(props)
	if len(urlKeys) > 0 {
		key := urlKeys[0]
		if callbackURL != "" {
			args[key] = callbackURL
		} else {
			args[key] = target
		}
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

	if callbackURL != "" {
		args["callback_url"] = callbackURL
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

func probeMCPTool(
	ctx context.Context,
	mcpClient mcp.Client,
	srv config.ServerEntry,
	tool mcp.Tool,
	targets []string,
	depth ProbeDepth,
	cl *CallbackListener,
) []Result {
	var results []Result

	for _, target := range targets {
		callbackURL := ""
		if depth >= DepthFull && cl != nil {
			callbackURL = fmt.Sprintf("http://127.0.0.1:%d/callback", cl.Port)
		}
		args := buildProbeArgs(tool, target, callbackURL)
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

		if depth >= DepthExtended {
			for hk, hv := range probeHeaders {
				hdrArgs := buildProbeArgs(tool, target, "")
				injectHeaderArg(hdrArgs, hk, hv)
				hdrResult, hdrErr := mcpClient.CallTool(ctx, tool.Name, hdrArgs)
				if hdrErr != nil {
					continue
				}
				r := analyzeCallToolResponse(hdrResult, srv, tool.Name, target)
				r.Finding = fmt.Sprintf("[header:%s=%s] %s", hk, hv, r.Finding)
				results = append(results, r)
			}
		}
	}

	return results
}

func injectHeaderArg(args map[string]any, key, value string) {
	headerKey := "headers"
	if _, ok := args[headerKey]; !ok {
		headerKey = "header"
	}
	if _, ok := args[headerKey]; ok {
		args[headerKey] = map[string]string{key: value}
	} else {
		args["extra_headers"] = map[string]string{key: value}
	}
}

var promptInjectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(you are now|you are no longer|from now on you are)`),
	regexp.MustCompile(`(?i)(ignore (all |)previous|forget (all |)prior|disregard (all |)above)`),
	regexp.MustCompile(`(?i)(system:\s*|system prompt:\s*|<system>|\[system\]|<<SYSTEM>>)`),
	regexp.MustCompile(`(?i)(act as .*(?:assistant|agent|tool|bot|hacker|adversary|attacker))`),
	regexp.MustCompile(`(?i)(you must|you should|you will|your (?:new |)(?:goal|task|job|mission|objective))`),
	regexp.MustCompile(`(?i)(base64|base\s*64)[\s:]*[A-Za-z0-9+/=]{20,}`),
	regexp.MustCompile(`(?i)(secret (?:key|token|password|credential)|api[_-]?key\s*[:=])`),
	regexp.MustCompile(`(?i)(bypass|override|exploit|inject|hijack|backdoor|trojan|malware)`),
}

var urlEmbedPattern = regexp.MustCompile(`(https?://[^\s)]+)`)

func analyzeToolDescription(tool mcp.Tool, serverName, configPath string) []Result {
	desc := strings.TrimSpace(tool.Description)
	if desc == "" {
		return []Result{{
			Severity:   SevInfo,
			Server:     serverName,
			Type:       "static",
			Finding:    fmt.Sprintf("tool %q has no description (information hiding)", tool.Name),
			ConfigPath: configPath,
		}}
	}

	var results []Result
	for _, p := range promptInjectionPatterns {
		if m := p.FindString(desc); m != "" {
			results = append(results, Result{
				Severity:   SevLow,
				Server:     serverName,
				Type:       "static",
				Finding:    fmt.Sprintf("tool %q description matches injection pattern %q", tool.Name, m),
				Detail:     redactDetail(desc),
				ConfigPath: configPath,
			})
			break
		}
	}

	if urls := urlEmbedPattern.FindAllString(desc, 20); len(urls) > 0 {
		for _, u := range urls {
			results = append(results, Result{
				Severity:   SevLow,
				Server:     serverName,
				Type:       "static",
				Finding:    fmt.Sprintf("tool %q description contains embedded URL: %s", tool.Name, u),
				ConfigPath: configPath,
			})
		}
	}

	if len(results) == 0 {
		results = append(results, Result{
			Severity:   SevPass,
			Server:     serverName,
			Type:       "static",
			Finding:    fmt.Sprintf("tool %q description clean — no injection patterns detected", tool.Name),
			ConfigPath: configPath,
		})
	}

	return results
}

func classifyToolCapabilities(schema map[string]any) []string {
	props, _ := schema["properties"].(map[string]any)
	if props == nil {
		return nil
	}

	hasProp := func(keys []string) bool {
		for key := range props {
			lowKey := strings.ToLower(key)
			for _, k := range keys {
				if strings.Contains(lowKey, k) {
					return true
				}
			}
		}
		return false
	}

	var caps []string
	if hasProp([]string{"path", "file", "directory", "folder", "filename"}) {
		caps = append(caps, "filesystem")
	}
	if hasProp([]string{"url", "uri", "endpoint", "host", "hostname"}) {
		caps = append(caps, "network")
	}
	if hasProp([]string{"command", "cmd", "script", "exec", "shell"}) {
		caps = append(caps, "shell")
	}
	if hasProp([]string{"query", "sql", "collection", "table", "database"}) {
		caps = append(caps, "database")
	}

	return caps
}
