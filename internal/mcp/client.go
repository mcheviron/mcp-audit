package mcp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

var ErrAuthRequired = errors.New("authentication required (401/403)")

var implementation = &sdkmcp.Implementation{
	Name:    "mcp-audit",
	Version: "0.1.0",
}

const DefaultTimeout = 30 * time.Second

type Client interface {
	Initialize(ctx context.Context) (*InitializeResult, error)
	ListTools(ctx context.Context) (*ListToolsResult, error)
	CallTool(ctx context.Context, toolName string, args map[string]any) (*CallToolResult, error)
	Close() error
}

type InitializeResult struct {
	ProtocolVersion string
	ServerName      string
	ServerVersion   string
}

type ListToolsResult struct {
	Tools []Tool
}

type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

type CallToolResult struct {
	Content []toolContent
	IsError bool
}

type toolContent struct {
	Type string
	Text string
}

type clientSession struct {
	session *sdkmcp.ClientSession
	closers []func() error
}

func (c *clientSession) Initialize(_ context.Context) (*InitializeResult, error) {
	ir := c.session.InitializeResult()
	if ir == nil {
		return nil, fmt.Errorf("initialize: no result")
	}
	info := ir.ServerInfo
	return &InitializeResult{
		ProtocolVersion: ir.ProtocolVersion,
		ServerName:      info.Name,
		ServerVersion:   info.Version,
	}, nil
}

func (c *clientSession) ListTools(ctx context.Context) (*ListToolsResult, error) {
	res, err := c.session.ListTools(ctx, nil)
	if err != nil {
		return nil, err
	}
	tools := make([]Tool, len(res.Tools))
	for i, t := range res.Tools {
		tools[i] = Tool{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: toMap(t.InputSchema),
		}
	}
	return &ListToolsResult{Tools: tools}, nil
}

func (c *clientSession) CallTool(ctx context.Context, toolName string, args map[string]any) (*CallToolResult, error) {
	res, err := c.session.CallTool(ctx, &sdkmcp.CallToolParams{
		Name:      toolName,
		Arguments: args,
	})
	if err != nil {
		return nil, err
	}
	out := &CallToolResult{IsError: res.IsError}
	for _, content := range res.Content {
		switch c := content.(type) {
		case *sdkmcp.TextContent:
			if c.Text != "" {
				out.Content = append(out.Content, toolContent{Type: "text", Text: c.Text})
			}
		case *sdkmcp.EmbeddedResource:
			if c.Resource != nil && c.Resource.Text != "" {
				out.Content = append(out.Content, toolContent{Type: "resource", Text: c.Resource.Text})
			}
		case *sdkmcp.ResourceLink:
			if c.Description != "" {
				out.Content = append(out.Content, toolContent{Type: "resource_link", Text: c.Description})
			}
		}
	}
	return out, nil
}

func (c *clientSession) Close() error {
	var firstErr error
	for _, closer := range c.closers {
		if err := closer(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if err := c.session.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

type sessionClient struct {
	session *clientSession
}

func (s *sessionClient) ListTools(ctx context.Context) (*ListToolsResult, error) {
	if s.session == nil {
		return nil, fmt.Errorf("not connected")
	}
	return s.session.ListTools(ctx)
}

func (s *sessionClient) CallTool(ctx context.Context, toolName string, args map[string]any) (*CallToolResult, error) {
	if s.session == nil {
		return nil, fmt.Errorf("not connected")
	}
	return s.session.CallTool(ctx, toolName, args)
}

func (s *sessionClient) Close() error {
	if s.session != nil {
		return s.session.Close()
	}
	return nil
}

func toMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	return m
}

func NewStdioClient(ctx context.Context, command string, args []string, _ time.Duration) Client {
	cmd := exec.CommandContext(ctx, command, args...)
	tr := &sdkmcp.CommandTransport{Command: cmd}
	return &stdioClient{transport: tr, cmd: cmd}
}

type stdioClient struct {
	transport *sdkmcp.CommandTransport
	cmd       *exec.Cmd
	session   *clientSession
}

func (s *stdioClient) Initialize(ctx context.Context) (*InitializeResult, error) {
	sdkClient := sdkmcp.NewClient(implementation, nil)
	session, err := sdkClient.Connect(ctx, s.transport, nil)
	if err != nil {
		return nil, fmt.Errorf("stdio connect: %w", err)
	}
	s.session = &clientSession{session: session}
	return s.session.Initialize(ctx)
}

func (s *stdioClient) ListTools(ctx context.Context) (*ListToolsResult, error) {
	if s.session == nil {
		return nil, fmt.Errorf("not connected")
	}
	return s.session.ListTools(ctx)
}

func (s *stdioClient) CallTool(ctx context.Context, toolName string, args map[string]any) (*CallToolResult, error) {
	if s.session == nil {
		return nil, fmt.Errorf("not connected")
	}
	return s.session.CallTool(ctx, toolName, args)
}

func (s *stdioClient) Close() error {
	if s.session != nil {
		return s.session.Close()
	}
	return nil
}

func newHTTPClient(
	token string, headers map[string]string, certFile, keyFile string, timeout time.Duration,
) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load TLS keypair: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	base := &http.Transport{TLSClientConfig: tlsConfig}
	rt := &authRoundTripper{
		base:       base,
		authHeader: "Bearer " + token,
		headers:    headers,
	}
	return &http.Client{Transport: rt, Timeout: timeout}, nil
}

type authRoundTripper struct {
	base       http.RoundTripper
	authHeader string
	headers    map[string]string
}

func (a *authRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if a.authHeader != "" {
		req.Header.Set("Authorization", a.authHeader)
	}
	for k, v := range a.headers {
		req.Header.Set(k, v)
	}
	return a.base.RoundTrip(req)
}

func newStreamableTransport(url string, httpClient *http.Client) *sdkmcp.StreamableClientTransport {
	return &sdkmcp.StreamableClientTransport{
		Endpoint:   url,
		HTTPClient: httpClient,
	}
}

func newSSETransport(url string, httpClient *http.Client) *sdkmcp.SSEClientTransport {
	return &sdkmcp.SSEClientTransport{
		Endpoint:   url,
		HTTPClient: httpClient,
	}
}

func NewHTTPClient(
	url string, timeout time.Duration, token string, headers map[string]string, certFile, keyFile string,
) (Client, error) {
	httpClient, err := newHTTPClient(token, headers, certFile, keyFile, timeout)
	if err != nil {
		return nil, err
	}
	tr := newStreamableTransport(url, httpClient)
	return &httpClientWrapper{transport: tr, url: url, httpClient: httpClient}, nil
}

func NewSSEClient(
	url string, timeout time.Duration, token string, headers map[string]string, certFile, keyFile string,
) (Client, error) {
	httpClient, err := newHTTPClient(token, headers, certFile, keyFile, timeout)
	if err != nil {
		return nil, err
	}
	tr := newSSETransport(url, httpClient)
	return &httpClientWrapper{transport: tr, url: url, httpClient: httpClient}, nil
}

func NewAutoClient(
	url string, timeout time.Duration, token string, headers map[string]string, certFile, keyFile string,
) (Client, error) {
	httpClient, err := newHTTPClient(token, headers, certFile, keyFile, timeout)
	if err != nil {
		return nil, err
	}
	return &autoClient{url: url, httpClient: httpClient}, nil
}

type httpClientWrapper struct {
	transport  sdkmcp.Transport
	url        string
	httpClient *http.Client
	sessionClient
}

func (h *httpClientWrapper) Initialize(ctx context.Context) (*InitializeResult, error) {
	sdkClient := sdkmcp.NewClient(implementation, nil)
	session, err := sdkClient.Connect(ctx, h.transport, nil)
	if err != nil {
		return nil, wrapAuthError(err)
	}
	h.session = &clientSession{session: session}
	return h.session.Initialize(ctx)
}

type autoClient struct {
	url        string
	httpClient *http.Client
	sessionClient
}

func (a *autoClient) Initialize(ctx context.Context) (*InitializeResult, error) {
	sdkClient := sdkmcp.NewClient(implementation, nil)
	streamable := newStreamableTransport(a.url, a.httpClient)
	session, err := sdkClient.Connect(ctx, streamable, nil)
	if err == nil {
		a.session = &clientSession{session: session}
		return a.session.Initialize(ctx)
	}
	authErr := wrapAuthError(err)
	if errors.Is(authErr, ErrAuthRequired) {
		return nil, authErr
	}
	sse := newSSETransport(a.url, a.httpClient)
	session, err = sdkClient.Connect(ctx, sse, nil)
	if err != nil {
		return nil, wrapAuthError(fmt.Errorf("connect failed (streamable and SSE): %w", err))
	}
	a.session = &clientSession{session: session}
	return a.session.Initialize(ctx)
}

func wrapAuthError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.Contains(msg, "401") || strings.Contains(msg, "403") ||
		strings.Contains(msg, "Unauthorized") || strings.Contains(msg, "Forbidden") {
		return fmt.Errorf("%w: %w", ErrAuthRequired, err)
	}
	return err
}
