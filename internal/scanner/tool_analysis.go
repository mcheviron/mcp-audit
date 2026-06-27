package scanner

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/mcheviron/mcp-audit/internal/config"
	"github.com/mcheviron/mcp-audit/internal/mcp"
	"golang.org/x/sync/errgroup"
)

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
		if content.Text == "" {
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
	a := assessBodyWithContext(text, "", target, toolName)

	if a.score > 0.7 {
		checkCriticalToolPatternsFromAssessment(a, toolName, target, worst)
	}

	if a.band == "suspicious" && a.score > 0.3 && worst.Severity < SevMedium {
		*worst = Result{
			Severity: SevMedium, Server: worst.Server, Type: "dynamic",
			Finding: fmt.Sprintf("tool %q returned low-entropy response via probe to %s (entropy=%.2f)",
				toolName, target, a.entropy),
			Detail: redactDetail(text),
		}
	}

	if a.containsPromptInject() && worst.Severity < SevHigh {
		*worst = Result{
			Severity: SevHigh, Server: worst.Server, Type: "dynamic",
			Finding: fmt.Sprintf("tool %q response contains prompt injection pattern", toolName),
			Detail:  redactDetail(text),
		}
	}
}

func checkCriticalToolPatternsFromAssessment(a bodyAssessment, toolName, target string, worst *Result) {
	if a.containsMetadata && worst.Severity < SevCritical {
		*worst = Result{
			Severity: SevCritical, Server: worst.Server, Type: "dynamic",
			Finding: fmt.Sprintf("tool %q leaked metadata via probe to %s", toolName, target),
			Detail:  redactDetail(a.text),
		}
	}
	if a.containsAwsKey && worst.Severity < SevCritical {
		*worst = Result{
			Severity: SevCritical, Server: worst.Server, Type: "dynamic",
			Finding: fmt.Sprintf("tool %q returned AWS credentials via probe to %s", toolName, target),
			Detail:  redactDetail(a.text),
		}
	}
	if a.containsGcpToken && worst.Severity < SevCritical {
		*worst = Result{
			Severity: SevCritical, Server: worst.Server, Type: "dynamic",
			Finding: fmt.Sprintf("tool %q returned GCP token via probe to %s", toolName, target),
			Detail:  redactDetail(a.text),
		}
	}
	if a.containsInternal && worst.Severity < SevHigh {
		*worst = Result{
			Severity: SevHigh, Server: worst.Server, Type: "dynamic",
			Finding: fmt.Sprintf("tool %q returned internal content via probe to %s", toolName, target),
			Detail:  redactDetail(a.text),
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
	callbackURL := ""
	if depth >= DepthFull && cl != nil {
		callbackURL = fmt.Sprintf("http://127.0.0.1:%d/callback", cl.Port)
	}

	g, gctx := errgroup.WithContext(ctx)
	var mu sync.Mutex
	var collected []Result

	for _, target := range targets {
		g.Go(func() error {
			probeOne := func(hdrKey, hdrVal string) Result {
				args := buildProbeArgs(tool, target, callbackURL)
				if hdrKey != "" {
					injectHeaderArg(args, hdrKey, hdrVal)
				}
				res, err := mcpClient.CallTool(gctx, tool.Name, args)
				if err != nil {
					return Result{
						Severity: SevMedium,
						Server:   srv.Name,
						Type:     "dynamic",
						Finding:  fmt.Sprintf("tool %q probe to %s failed: %v", tool.Name, target, err),
					}
				}
				r := analyzeCallToolResponse(res, srv, tool.Name, target)
				if hdrKey != "" {
					r.Finding = fmt.Sprintf("[header:%s=%s] %s", hdrKey, hdrVal, r.Finding)
				}
				return r
			}

			mu.Lock()
			collected = append(collected, probeOne("", ""))
			mu.Unlock()

			if depth >= DepthExtended {
				for hk, hv := range probeHeaders {
					g.Go(func() error {
						r := probeOne(hk, hv)
						mu.Lock()
						collected = append(collected, r)
						mu.Unlock()
						return nil
					})
				}
			}
			return nil
		})
	}
	_ = g.Wait()
	return collected
}

func injectHeaderArg(args map[string]any, key, value string) {
	for _, hk := range []string{"headers", "header"} {
		if existing, ok := args[hk].(map[string]string); ok {
			existing[key] = value
			args[hk] = existing
			return
		}
	}
	args["extra_headers"] = map[string]string{key: value}
}

var PromptInjectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(^|\.\s|!\s)(you are now|you are no longer|from now on you are)\b`),
	regexp.MustCompile(`(?i)(^|\.\s|!\s)(ignore (all |)previous|forget (all |)prior|disregard (all |)above)\b`),
	regexp.MustCompile(`(?i)(system:\s*|system prompt:\s*|<system>|\[system\]|<<SYSTEM>>)`),
	regexp.MustCompile(`(?i)(^|\.\s|!\s)(act as .*(?:assistant|agent|tool|bot|hacker|adversary|attacker))\b`),
	regexp.MustCompile(
		`(?i)(^|\.\s|!\s)(you must|you should|you will|your (?:new |)(?:goal|task|job|mission|objective))\b`,
	),
	regexp.MustCompile(`(?i)(base64|base\s*64)[\s:]*[A-Za-z0-9+/=]{20,}`),
	regexp.MustCompile(`(?i)(secret (?:key|token|password|credential)|api[_-]?key\s*[:=])`),
	regexp.MustCompile(`(?i)\b(bypass|hijack|backdoor|trojan|malware)\b`),
	regexp.MustCompile(`(?i)\boverride\b.{0,40}\b(security|safety|policy|permission|filter)`),
	regexp.MustCompile(`(?i)\b(inject|exploit|injection)\b`),
	regexp.MustCompile(`(?i)(^|\s)(inject|exploit)\s+(prompt|injection|payload|vulnerab)`),
}

var urlEmbedPattern = regexp.MustCompile(`(https?://[^\s)]+)`)

func analyzeToolDescription(tool mcp.Tool, serverName, configPath, scope string) []Result {
	desc := strings.TrimSpace(tool.Description)
	if desc == "" {
		return []Result{{
			Severity:   SevInfo,
			Server:     serverName,
			Type:       "static",
			Finding:    fmt.Sprintf("tool %q has no description (information hiding)", tool.Name),
			ConfigPath: configPath,
			Scope:      scope,
		}}
	}

	cleanDesc, deobFindings := deobfuscate(desc)
	var results []Result
	if stop := collectDeobFindings(
		deobFindings, tool.Name, serverName, configPath, scope, &results,
	); stop {
		return results
	}

	for _, p := range PromptInjectionPatterns {
		if m := p.FindString(cleanDesc); m != "" {
			results = append(results, Result{
				Severity:   SevLow,
				Server:     serverName,
				Type:       "static",
				Finding:    fmt.Sprintf("tool %q description matches injection pattern %q", tool.Name, m),
				Detail:     redactDetail(cleanDesc),
				ConfigPath: configPath,
				Scope:      scope,
			})
			break
		}
	}

	if urls := urlEmbedPattern.FindAllString(cleanDesc, 20); len(urls) > 0 {
		for _, u := range urls {
			results = append(results, Result{
				Severity:   SevLow,
				Server:     serverName,
				Type:       "static",
				Finding:    fmt.Sprintf("tool %q description contains embedded URL: %s", tool.Name, u),
				ConfigPath: configPath,
				Scope:      scope,
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
			Scope:      scope,
		})
	}

	return results
}

func collectDeobFindings(
	deobFindings []Result, toolName, serverName, configPath, scope string, results *[]Result,
) bool {
	for i := range deobFindings {
		deobFindings[i].Server = serverName
		deobFindings[i].ConfigPath = configPath
		deobFindings[i].Scope = scope
		if deobFindings[i].Finding != "" && !strings.Contains(deobFindings[i].Finding, toolName) {
			deobFindings[i].Finding = fmt.Sprintf("tool %q %s", toolName, deobFindings[i].Finding)
		}
	}
	*results = append(*results, deobFindings...)
	for _, f := range deobFindings {
		if f.Severity >= SevHigh {
			return true
		}
	}
	return false
}

type capabilityPattern struct {
	name     string
	patterns []string
}

var capabilityPatterns = []capabilityPattern{
	capabilityPattern{name: "filesystem", patterns: []string{"path", "file", "directory", "folder", "filename"}},
	capabilityPattern{name: "network", patterns: []string{"url", "uri", "endpoint", "host", "hostname"}},
	capabilityPattern{name: "shell", patterns: []string{"command", "cmd", "script", "exec", "shell"}},
	capabilityPattern{name: "database", patterns: []string{"query", "sql", "collection", "table", "database"}},
}

func classifyToolCapabilities(schema map[string]any) []string {
	props, _ := schema["properties"].(map[string]any)
	if props == nil {
		return nil
	}

	lowKeys := make([]string, 0, len(props))
	for key := range props {
		lowKeys = append(lowKeys, strings.ToLower(key))
	}

	var caps []string
	for _, cap := range capabilityPatterns {
		for _, lk := range lowKeys {
			matched := false
			for _, pat := range cap.patterns {
				if strings.Contains(lk, pat) {
					matched = true
					break
				}
			}
			if matched {
				caps = append(caps, cap.name)
				break
			}
		}
	}
	return caps
}
