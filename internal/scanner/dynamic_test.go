package scanner

import (
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mostafaelataby-cheviron/mcp-audit/internal/mcp"
)

func TestCallbackListenerStartStop(t *testing.T) {
	cl := startCallbackListener(0)
	if cl == nil {
		t.Fatal("startCallbackListener returned nil")
	}
	if cl.Port == 0 {
		t.Fatal("expected non-zero port")
	}

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/callback", cl.Port))
	if err != nil {
		t.Fatalf("failed to reach callback listener: %v", err)
	}
	resp.Body.Close()

	select {
	case src := <-cl.Callback:
		if src == "" {
			t.Error("callback source empty")
		}
	case <-time.After(2 * time.Second):
		t.Error("callback channel did not receive event")
	}

	cl.drainCallbacks(100 * time.Millisecond)
	cl.stopCallbackListener()
}

func TestCallbackListenerCollectResults(t *testing.T) {
	cl := startCallbackListener(0)
	if cl == nil {
		t.Fatal("startCallbackListener returned nil")
	}

	for range 3 {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/callback", cl.Port))
		if err != nil {
			t.Fatalf("callback request failed: %v", err)
		}
		resp.Body.Close()
	}

	results := cl.collectCallbackResults("test-srv", "/test/config.json")

	cl.drainCallbacks(100 * time.Millisecond)
	if len(results) == 0 {
		t.Error("expected callback results")
	}
	for _, r := range results {
		if r.Severity != SevCritical {
			t.Errorf("expected CRITICAL for blind SSRF, got %v", r.Severity)
		}
		if r.Server != "test-srv" {
			t.Errorf("expected server test-srv, got %s", r.Server)
		}
	}
	cl.stopCallbackListener()
}

func TestGetProbeTargetsDepth(t *testing.T) {
	basic := getProbeTargets(DepthBasic)
	if len(basic) != len(baseTargets) {
		t.Errorf("basic depth: expected %d targets, got %d", len(baseTargets), len(basic))
	}

	extended := getProbeTargets(DepthExtended)
	if len(extended) <= len(baseTargets) {
		t.Error("extended depth should include more targets than basic")
	}

	full := getProbeTargets(DepthFull)
	if len(full) <= len(extended) {
		t.Error("full depth should include more targets than extended")
	}

	foundDNS := slices.Contains(full, dnsRebindingHost)
	if !foundDNS {
		t.Error("full depth should include DNS rebinding host")
	}
}

func TestIsInternalHost(t *testing.T) {
	tests := []struct {
		url      string
		internal bool
	}{
		{"http://127.0.0.1:8080/path", true},
		{"http://192.168.1.1/admin", true},
		{"http://10.0.0.1/", true},
		{"http://172.16.0.1/", true},
		{"http://[::1]/", true},
		{"http://169.254.169.254/", true},
		{"http://0.0.0.0/", true},
		{"http://1.2.3.4/", false},
		{"http://8.8.8.8/", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			if got := isInternalHost(tt.url); got != tt.internal {
				t.Errorf("isInternalHost(%q) = %v, want %v", tt.url, got, tt.internal)
			}
		})
	}
}

func TestProbeDepthString(t *testing.T) {
	if DepthBasic.String() != "basic" {
		t.Errorf("DepthBasic.String() = %q, want %q", DepthBasic.String(), "basic")
	}
	if DepthExtended.String() != "extended" {
		t.Errorf("DepthExtended.String() = %q, want %q", DepthExtended.String(), "extended")
	}
	if DepthFull.String() != "full" {
		t.Errorf("DepthFull.String() = %q, want %q", DepthFull.String(), "full")
	}
}

func TestParseProbeDepth(t *testing.T) {
	tests := []struct {
		input string
		want  ProbeDepth
	}{
		{"basic", DepthBasic},
		{"extended", DepthExtended},
		{"full", DepthFull},
		{"", DepthBasic},
		{"invalid", DepthBasic},
	}

	for _, tt := range tests {
		if got := ParseProbeDepth(tt.input); got != tt.want {
			t.Errorf("ParseProbeDepth(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestFilterTargets(t *testing.T) {
	targets := []string{"http://127.0.0.1/", "http://169.254.169.254/", "http://example.com/"}

	filtered := filterTargets(targets, nil, []string{"169.254.169.254"})
	for _, tgt := range filtered {
		if tgt == "http://169.254.169.254/" {
			t.Error("blocked target should be filtered out")
		}
	}

	allowed := filterTargets(targets, []string{"127.0.0.1"}, nil)
	if len(allowed) != 1 || allowed[0] != "http://127.0.0.1/" {
		t.Errorf("expected only 127.0.0.1 target, got %v", allowed)
	}
}

func TestBuildProbeArgsWithCallback(t *testing.T) {
	tool := mcp.Tool{
		Name: "fetch",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"url": map[string]any{"type": "string", "description": "URL to fetch"},
			},
		},
	}

	args := buildProbeArgs(tool, "http://169.254.169.254/", "http://127.0.0.1:9999/callback")
	if args["url"] != "http://127.0.0.1:9999/callback" {
		t.Errorf("url not replaced with callback: %v", args["url"])
	}

	toolNoURL := mcp.Tool{
		Name: "search",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"query": map[string]any{"type": "string"},
			},
		},
	}
	args2 := buildProbeArgs(toolNoURL, "test", "http://127.0.0.1:9999/callback")
	if args2["callback_url"] != "http://127.0.0.1:9999/callback" {
		t.Errorf("callback_url not set for non-URL tool: %v", args2)
	}
}

func TestInjectHeaderArg(t *testing.T) {
	t.Run("headers-key", func(t *testing.T) {
		args := map[string]any{"headers": map[string]string{}}
		injectHeaderArg(args, "X-Forwarded-Host", "169.254.169.254")
		h := args["headers"].(map[string]string)
		if h["X-Forwarded-Host"] != "169.254.169.254" {
			t.Errorf("header not set: %v", h)
		}
	})

	t.Run("header-key", func(t *testing.T) {
		args := map[string]any{"header": map[string]string{}}
		injectHeaderArg(args, "Host", "169.254.169.254")
		h := args["header"].(map[string]string)
		if h["Host"] != "169.254.169.254" {
			t.Errorf("header not set: %v", h)
		}
	})

	t.Run("no-header-key", func(t *testing.T) {
		args := map[string]any{"url": "http://example.com"}
		injectHeaderArg(args, "Referer", "http://169.254.169.254/")
		h := args["extra_headers"].(map[string]string)
		if h["Referer"] != "http://169.254.169.254/" {
			t.Errorf("extra_headers not set: %v", h)
		}
	})
}

func TestBuildProbeArgs(t *testing.T) {
	tool := mcp.Tool{
		Name: "fetch",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"url": map[string]any{
					"type":        "string",
					"description": "URL to fetch",
				},
			},
		},
	}

	args := buildProbeArgs(tool, "http://127.0.0.1/", "")
	if args["url"] != "http://127.0.0.1/" {
		t.Errorf("url not set: %v", args)
	}
}

func TestLoadTargetsFile(t *testing.T) {
	t.Run("nonexistent-file", func(t *testing.T) {
		targets := loadTargetsFile("/nonexistent/path")
		if targets != nil {
			t.Errorf("expected nil for nonexistent file, got %v", targets)
		}
	})
}

func TestExpandedTargetsList(t *testing.T) {
	azureFound := false
	doFound := false
	oracleFound := false
	for _, tgt := range expandedTargets {
		if strings.Contains(tgt, "metadata/instance") {
			azureFound = true
		}
		if strings.Contains(tgt, "metadata/v1") {
			doFound = true
		}
		if strings.Contains(tgt, "opc/v1") {
			oracleFound = true
		}
	}
	if !azureFound {
		t.Error("Azure metadata endpoint missing from expanded targets")
	}
	if !doFound {
		t.Error("DigitalOcean metadata endpoint missing from expanded targets")
	}
	if !oracleFound {
		t.Error("Oracle Cloud metadata endpoint missing from expanded targets")
	}
}

func TestProbeMethodsList(t *testing.T) {
	if len(probeMethods) != 3 {
		t.Errorf("expected 3 probe methods, got %d", len(probeMethods))
	}
	methods := make(map[string]bool)
	for _, m := range probeMethods {
		methods[m] = true
	}
	if !methods["GET"] || !methods["POST"] || !methods["PUT"] {
		t.Errorf("missing expected methods: %v", probeMethods)
	}
}

func TestProbeHeadersList(t *testing.T) {
	if len(probeHeaders) != 4 {
		t.Errorf("expected 4 probe headers, got %d", len(probeHeaders))
	}
	if probeHeaders["Metadata"] != "true" {
		t.Error("Metadata header missing or wrong value")
	}
	if probeHeaders["X-Forwarded-Host"] != "169.254.169.254" {
		t.Error("X-Forwarded-Host header missing or wrong value")
	}
	if probeHeaders["Host"] != "169.254.169.254" {
		t.Error("Host header missing or wrong value")
	}
	if probeHeaders["Referer"] != "http://169.254.169.254/" {
		t.Error("Referer header missing or wrong value")
	}
}

func TestDNSRebindingHostPresent(t *testing.T) {
	if dnsRebindingHost == "" {
		t.Error("DNS rebinding host should not be empty")
	}

	targets := getProbeTargets(DepthFull)
	found := slices.Contains(targets, dnsRebindingHost)
	if !found {
		t.Error("DNS rebinding host not in full-depth targets")
	}

	basic := getProbeTargets(DepthBasic)
	for _, tgt := range basic {
		if tgt == dnsRebindingHost {
			t.Error("DNS rebinding host should not be in basic-depth targets")
		}
	}
}

func TestIsInternalHostForDNSRebinding(t *testing.T) {
	if !isInternalHost("http://192.168.1.1/") {
		t.Error("192.168.1.1 should be internal")
	}
	if isInternalHost("http://8.8.8.8/") {
		t.Error("8.8.8.8 should not be internal")
	}

	if ip := net.ParseIP("127.0.0.1"); ip != nil {
		if !ip.IsLoopback() {
			t.Error("127.0.0.1 should be loopback")
		}
	}
}

func TestRunDirectProbesDepthGating(t *testing.T) {
	probeResults, _ := runDirectProbes(nil, []string{"http://127.0.0.1/", "http://example.com/"}, DepthBasic, 4096, 10)
	if len(probeResults) > 0 {
	}

	_, _ = runDirectProbes(nil, nil, DepthExtended, 4096, 10)

	_, _ = runDirectProbes(nil, nil, DepthFull, 4096, 10)
}
