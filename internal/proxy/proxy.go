package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/mostafaelataby-cheviron/mcp-audit/internal/scanner"
)

type Config struct {
	ListenAddr      string
	TargetURL       string
	BlockCritical   bool
	MaxResponseSize int64
}

type Proxy struct {
	config    Config
	targetURL *url.URL
	inspector *Inspector
}

func (p *Proxy) Handler() http.Handler {
	targetURL := p.targetURL
	if targetURL == nil {
		var err error
		targetURL, err = url.Parse(p.config.TargetURL)
		if err != nil {
			targetURL = &url.URL{Scheme: "http", Host: "localhost"}
		}
	}

	var requestMethod string

	director := func(req *http.Request) {
		req.URL.Scheme = targetURL.Scheme
		req.URL.Host = targetURL.Host
		req.URL.Path = targetURL.Path
		if req.URL.Path == "" {
			req.URL.Path = "/"
		}
		req.Host = targetURL.Host

		if req.Body != nil && req.Body != http.NoBody {
			var buf bytes.Buffer
			limited := io.LimitReader(req.Body, 4096)
			n, err := io.Copy(&buf, limited)
			if err != nil {
				slog.Debug("read request body for method extraction", "err", err)
			}
			bodyBytes := buf.Bytes()
			requestMethod = extractMethodFromBody(bodyBytes)
			p.inspectRequestFromBody(bodyBytes, requestMethod)
			if n == 4096 {
				rest, readErr := io.ReadAll(req.Body)
				if readErr != nil {
					slog.Debug("read remaining request body", "err", readErr)
				}
				bodyBytes = append(bodyBytes, rest...)
			}
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
	}

	return &httputil.ReverseProxy{
		Director: director,
		ModifyResponse: func(resp *http.Response) error {
			return p.inspectAndModify(resp, requestMethod)
		},
	}
}

func (p *Proxy) Inspector() *Inspector {
	return p.inspector
}

func (p *Proxy) inspectRequestFromBody(body []byte, method string) {
	if len(body) == 0 || method != "tools/call" {
		return
	}

	var req struct {
		Params map[string]any `json:"params"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return
	}

	p.inspector.InspectRequest(method, req.Params)
}

func New(cfg Config) *Proxy {
	if cfg.MaxResponseSize <= 0 {
		cfg.MaxResponseSize = 65536
	}
	return &Proxy{
		config:    cfg,
		inspector: NewInspector(),
	}
}

func (p *Proxy) Start() error {
	target, err := url.Parse(p.config.TargetURL)
	if err != nil {
		return fmt.Errorf("parse target URL: %w", err)
	}
	p.targetURL = target

	slog.Info("proxy listening", "addr", p.config.ListenAddr, "target", p.config.TargetURL)
	if p.config.BlockCritical {
		slog.Info("block-critical mode enabled")
	}

	srv := &http.Server{
		Addr:              p.config.ListenAddr,
		Handler:           p.Handler(),
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.ListenAndServe()
}

func (p *Proxy) inspectAndModify(resp *http.Response, method string) error {
	if resp.Body == nil {
		return nil
	}

	limited := io.LimitReader(resp.Body, p.config.MaxResponseSize)
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, limited); err != nil {
		return fmt.Errorf("read response body: %w", err)
	}
	if err := resp.Body.Close(); err != nil {
		slog.Debug("close upstream body", "err", err)
	}

	ct := resp.Header.Get("Content-Type")
	if ct == "application/json" || ct == "text/event-stream" {
		if method == "" {
			method = "unknown"
		}
		p.inspectJSONBody(buf.Bytes(), method)
	}

	if p.config.BlockCritical && p.inspector.HasCritical() {
		crit := p.latestCritical()
		blockRes := map[string]any{
			"jsonrpc": "2.0",
			"error": map[string]any{
				"code":    -32000,
				"message": fmt.Sprintf("Blocked by mcp-audit: %s", crit.Message),
			},
		}
		blockBody, err := json.Marshal(blockRes)
		if err != nil {
			return fmt.Errorf("marshal block response: %w", err)
		}

		resp.Body = io.NopCloser(bytes.NewReader(blockBody))
		resp.ContentLength = int64(len(blockBody))
		resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(blockBody)))
		resp.Header.Set("Content-Type", "application/json")
		resp.Header.Set("X-MCP-Audit-Blocked", "true")
		resp.StatusCode = http.StatusOK

		slog.Warn("blocked critical finding", "finding", crit.Message)
		return nil
	}

	resp.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))
	resp.ContentLength = int64(buf.Len())
	return nil
}

func (p *Proxy) inspectJSONBody(body []byte, method string) {
	if len(body) == 0 {
		return
	}

	if strings.HasPrefix(string(body), "{") {
		var rpcResp struct {
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error,omitempty"`
		}
		if err := json.Unmarshal(body, &rpcResp); err != nil {
			return
		}

		if rpcResp.Result != nil {
			p.inspector.InspectResponse(method, rpcResp.Result)
		}
	}
}

func (p *Proxy) latestCritical() *Finding {
	for i := len(p.inspector.Findings) - 1; i >= 0; i-- {
		if p.inspector.Findings[i].Severity == scanner.SevCritical {
			return &p.inspector.Findings[i]
		}
	}
	return nil
}

func extractMethodFromBody(body []byte) string {
	var req struct {
		Method string `json:"method"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return "unknown"
	}
	return req.Method
}
