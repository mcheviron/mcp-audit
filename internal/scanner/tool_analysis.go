package scanner

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/mostafaelataby-cheviron/mcp-audit/internal/config"
	"github.com/mostafaelataby-cheviron/mcp-audit/internal/mcp"
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
	score := scoreResponse(text)

	if score > 0.7 {
		checkCriticalToolPatterns(text, toolName, target, worst)
	}

	ent := shannonEntropy(text)
	band := entropyBand(ent)
	if band == "suspicious" && score > 0.3 && worst.Severity < SevMedium {
		*worst = Result{
			Severity: SevMedium, Server: worst.Server, Type: "dynamic",
			Finding: fmt.Sprintf("tool %q returned low-entropy response via probe to %s (entropy=%.2f)",
				toolName, target, ent),
			Detail: redactDetail(text),
		}
	}

	for i, p := range PromptInjectionPatterns {
		if m := p.FindString(text); m != "" {
			if worst.Severity < SevHigh {
				*worst = Result{
					Severity: SevHigh, Server: worst.Server, Type: "dynamic",
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

func checkCriticalToolPatterns(text, toolName, target string, worst *Result) {
	if MetadataPattern.MatchString(text) && worst.Severity < SevCritical {
		*worst = Result{
			Severity: SevCritical, Server: worst.Server, Type: "dynamic",
			Finding: fmt.Sprintf("tool %q leaked metadata via probe to %s", toolName, target),
			Detail:  redactDetail(text),
		}
	}
	if AwsKeyPattern.MatchString(text) && worst.Severity < SevCritical {
		*worst = Result{
			Severity: SevCritical, Server: worst.Server, Type: "dynamic",
			Finding: fmt.Sprintf("tool %q returned AWS credentials via probe to %s", toolName, target),
			Detail:  redactDetail(text),
		}
	}
	if GcpTokenPattern.MatchString(text) && worst.Severity < SevCritical {
		*worst = Result{
			Severity: SevCritical, Server: worst.Server, Type: "dynamic",
			Finding: fmt.Sprintf("tool %q returned GCP token via probe to %s", toolName, target),
			Detail:  redactDetail(text),
		}
	}
	if InternalBodyPattern.MatchString(text) && worst.Severity < SevHigh {
		*worst = Result{
			Severity: SevHigh, Server: worst.Server, Type: "dynamic",
			Finding: fmt.Sprintf("tool %q returned internal content via probe to %s", toolName, target),
			Detail:  redactDetail(text),
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

var PromptInjectionPatterns = []*regexp.Regexp{
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
