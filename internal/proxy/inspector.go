package proxy

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"

	"github.com/mcheviron/mcp-audit/internal/scanner"
)

var internalHostPattern = regexp.MustCompile(
	`(?i)(localhost|127\.0\.0\.1|192\.168\.|10\.\d+\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)`,
)

type Finding struct {
	Severity scanner.Severity
	Method   string
	Message  string
}

type Inspector struct {
	mu       sync.Mutex
	Findings []Finding
}

func NewInspector() *Inspector {
	return &Inspector{}
}

func (ins *Inspector) Add(f Finding) {
	ins.mu.Lock()
	defer ins.mu.Unlock()
	ins.Findings = append(ins.Findings, f)
}

func (ins *Inspector) HasCritical() bool {
	ins.mu.Lock()
	defer ins.mu.Unlock()
	for _, f := range ins.Findings {
		if f.Severity == scanner.SevCritical {
			return true
		}
	}
	return false
}

func (ins *Inspector) InspectRequest(method string, params any) {
	slog.Info("proxy request", "method", method)

	cp, ok := params.(map[string]any)
	if !ok {
		return
	}

	if method == "tools/call" {
		name, _ := cp["name"].(string)
		args, _ := cp["arguments"].(map[string]any)
		slog.Info("proxy tools/call", "tool", name)
		for key, val := range args {
			valStr := flattenToString(val)
			if scanned := scanForSSRFIndicator(key, valStr); len(scanned) > 0 {
				for _, s := range scanned {
					ins.Add(Finding{
						Severity: scanner.SevHigh,
						Method:   method,
						Message:  fmt.Sprintf("tool %q arg %q contains SSRF indicator: %s", name, key, s),
					})
				}
			}
		}
	}
}

func (ins *Inspector) InspectResponse(method string, result json.RawMessage) {
	if result == nil {
		return
	}

	slog.Info("proxy response", "method", method)

	switch method {
	case "tools/list":
		ins.inspectToolsList(result)
	case "tools/call":
		ins.inspectCallToolResult(result)
	}
}

func (ins *Inspector) inspectToolsList(result json.RawMessage) {
	var toolsResp struct {
		Tools []struct {
			Name        string         `json:"name"`
			Description string         `json:"description"`
			InputSchema map[string]any `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(result, &toolsResp); err != nil {
		return
	}

	for _, tool := range toolsResp.Tools {
		for _, p := range scanner.PromptInjectionPatterns {
			if m := p.FindString(tool.Description); m != "" {
				ins.Add(Finding{
					Severity: scanner.SevLow,
					Method:   "tools/list",
					Message:  fmt.Sprintf("tool %q description matches injection pattern %q", tool.Name, m),
				})
				break
			}
		}

		if strings.TrimSpace(tool.Description) == "" {
			ins.Add(Finding{
				Severity: scanner.SevInfo,
				Method:   "tools/list",
				Message:  fmt.Sprintf("tool %q has no description", tool.Name),
			})
		}
	}
}

func (ins *Inspector) inspectCallToolResult(result json.RawMessage) {
	var callResp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text,omitempty"`
		} `json:"content"`
		IsError bool `json:"isError,omitempty"`
	}
	if err := json.Unmarshal(result, &callResp); err != nil {
		return
	}

	for _, c := range callResp.Content {
		if c.Type != "text" {
			continue
		}

		if scanner.AwsKeyPattern.MatchString(c.Text) {
			ins.Add(Finding{
				Severity: scanner.SevCritical,
				Method:   "tools/call",
				Message:  "AWS credentials detected in tool response",
			})
		}
		if scanner.GcpTokenPattern.MatchString(c.Text) {
			ins.Add(Finding{
				Severity: scanner.SevCritical,
				Method:   "tools/call",
				Message:  "GCP access token detected in tool response",
			})
		}
		if scanner.MetadataPattern.MatchString(c.Text) {
			ins.Add(Finding{
				Severity: scanner.SevCritical,
				Method:   "tools/call",
				Message:  "cloud metadata exposed in tool response",
			})
		}
		if scanner.InternalBodyPattern.MatchString(c.Text) {
			ins.Add(Finding{
				Severity: scanner.SevHigh,
				Method:   "tools/call",
				Message:  "internal content returned in tool response",
			})
		}
		for _, p := range scanner.PromptInjectionPatterns {
			if m := p.FindString(c.Text); m != "" {
				ins.Add(Finding{
					Severity: scanner.SevHigh,
					Method:   "tools/call",
					Message:  fmt.Sprintf("tool response contains prompt injection pattern %q", m),
				})
				break
			}
		}
	}
}

func flattenToString(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

func scanForSSRFIndicator(key, val string) []string {
	ssrfKeys := []string{"url", "uri", "endpoint", "host", "hostname", "callback_url"}
	keyLower := strings.ToLower(key)
	for _, sk := range ssrfKeys {
		if strings.Contains(keyLower, sk) {
			if isInternalHost(val) {
				return []string{fmt.Sprintf("internal target: %s", val)}
			}
			if strings.Contains(val, "://") {
				return []string{fmt.Sprintf("URL parameter: %s", redactURL(val))}
			}
		}
	}
	return nil
}

func isInternalHost(target string) bool {
	return internalHostPattern.MatchString(target)
}

func redactURL(u string) string {
	for _, p := range scanner.RedactPatterns {
		if m := p.FindString(u); m != "" {
			u = p.ReplaceAllString(u, "[REDACTED]")
		}
	}
	if len(u) > 80 {
		return u[:80] + "..."
	}
	return u
}
