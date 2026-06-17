package mcp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

var ErrAuthRequired = errors.New("authentication required")

const DefaultTimeout = 5 * time.Second

type Transport interface {
	Send(ctx context.Context, method string, params any) (json.RawMessage, error)
	SetAuthToken(token string)
	SetAuthHeaders(headers map[string]string)
	SetTLS(certFile, keyFile string) error
	Close() error
}

type HTTPTransport struct {
	httpClient  *http.Client
	endpoint    string
	idSeq       int
	sessionID   string
	authHeaders map[string]string
	authToken   string
}

var _ Transport = (*HTTPTransport)(nil)

func NewHTTPTransport(endpoint string, timeout time.Duration) *HTTPTransport {
	return &HTTPTransport{
		httpClient: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		endpoint: endpoint,
	}
}

func (t *HTTPTransport) SetAuthToken(token string) {
	t.authToken = token
}

func (t *HTTPTransport) SetAuthHeaders(headers map[string]string) {
	t.authHeaders = headers
}

func (t *HTTPTransport) SetTLS(certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("load TLS key pair: %w", err)
	}
	t.httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		},
	}
	return nil
}

func (t *HTTPTransport) Send(ctx context.Context, method string, params any) (json.RawMessage, error) {
	t.idSeq++
	req := request{
		JSONRPC: "2.0",
		ID:      t.idSeq,
		Method:  method,
		Params:  params,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	if t.sessionID != "" {
		httpReq.Header.Set("Mcp-Session-Id", t.sessionID)
	}
	if t.authToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+t.authToken)
	}
	for k, v := range t.authHeaders {
		httpReq.Header.Set(k, v)
	}

	resp, err := t.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		t.sessionID = sid
	}

	limited := io.LimitReader(resp.Body, 4096)
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, limited); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("HTTP %d: %s: %w", resp.StatusCode, buf.String(), ErrAuthRequired)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, buf.String())
	}

	var rpcResp response
	if err := json.Unmarshal(buf.Bytes(), &rpcResp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	return rpcResp.Result, nil
}

func (t *HTTPTransport) Close() error {
	t.httpClient.CloseIdleConnections()
	return nil
}

type autoTransport struct {
	url     string
	timeout time.Duration
	mu      sync.Mutex
	http    *HTTPTransport
	sse     *sseTransport
	active  Transport
	failed  bool
}

var _ Transport = (*autoTransport)(nil)

func NewAutoTransport(url string, timeout time.Duration) Transport {
	return &autoTransport{
		url:     url,
		timeout: timeout,
		http:    NewHTTPTransport(url, timeout),
	}
}

func (a *autoTransport) Send(ctx context.Context, method string, params any) (json.RawMessage, error) {
	a.mu.Lock()
	if a.active != nil {
		tr := a.active
		a.mu.Unlock()
		return tr.Send(ctx, method, params)
	}
	a.mu.Unlock()

	result, err := a.http.Send(ctx, method, params)
	if err == nil {
		a.mu.Lock()
		a.active = a.http
		a.mu.Unlock()
		return result, nil
	}

	if errors.Is(err, ErrAuthRequired) {
		return nil, err
	}

	_ = a.http.Close()

	a.mu.Lock()
	if a.failed {
		a.mu.Unlock()
		return nil, err
	}
	a.failed = true
	a.sse = NewSSETransport(a.url, a.timeout)
	sse := a.sse
	a.mu.Unlock()

	result, err = sse.Send(ctx, method, params)
	if err == nil {
		a.mu.Lock()
		a.active = a.sse
		a.mu.Unlock()
		return result, nil
	}

	return nil, err
}

func (a *autoTransport) SetAuthToken(token string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.http.SetAuthToken(token)
	if a.sse != nil {
		a.sse.SetAuthToken(token)
	}
}

func (a *autoTransport) SetAuthHeaders(headers map[string]string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.http.SetAuthHeaders(headers)
	if a.sse != nil {
		a.sse.SetAuthHeaders(headers)
	}
}

func (a *autoTransport) SetTLS(certFile, keyFile string) error {
	return a.http.SetTLS(certFile, keyFile)
}

func (a *autoTransport) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	_ = a.http.Close()
	if a.sse != nil {
		_ = a.sse.Close()
	}
	return nil
}

type Client interface {
	Initialize(ctx context.Context) (*InitializeResult, error)
	ListTools(ctx context.Context) (*ListToolsResult, error)
	CallTool(ctx context.Context, toolName string, args map[string]any) (*CallToolResult, error)
}

type mcpClient struct {
	transport Transport
}

var _ Client = (*mcpClient)(nil)

func NewClient(transport Transport) Client {
	return &mcpClient{transport: transport}
}

func (c *mcpClient) Initialize(ctx context.Context) (*InitializeResult, error) {
	params := InitializeParams{
		ProtocolVersion: "2024-11-05",
		Capabilities: capabilities{
			Roots: rootsCapability{ListChanged: true},
		},
		ClientInfo: clientInfo{
			Name:    "mcp-audit",
			Version: "0.1.0",
		},
	}

	result, err := c.transport.Send(ctx, "initialize", params)
	if err != nil {
		return nil, fmt.Errorf("initialize: %w", err)
	}

	var initResult InitializeResult
	if err := json.Unmarshal(result, &initResult); err != nil {
		return nil, fmt.Errorf("initialize: %w", err)
	}
	return &initResult, nil
}

func (c *mcpClient) ListTools(ctx context.Context) (*ListToolsResult, error) {
	result, err := c.transport.Send(ctx, "tools/list", nil)
	if err != nil {
		return nil, fmt.Errorf("tools/list: %w", err)
	}

	var toolsResult ListToolsResult
	if err := json.Unmarshal(result, &toolsResult); err != nil {
		return nil, fmt.Errorf("tools/list: %w", err)
	}
	return &toolsResult, nil
}

func (c *mcpClient) CallTool(ctx context.Context, toolName string, args map[string]any) (*CallToolResult, error) {
	params := CallToolParams{
		Name:      toolName,
		Arguments: args,
	}

	result, err := c.transport.Send(ctx, "tools/call", params)
	if err != nil {
		return nil, fmt.Errorf("tools/call %s: %w", toolName, err)
	}

	var callResult CallToolResult
	if err := json.Unmarshal(result, &callResult); err != nil {
		return nil, fmt.Errorf("tools/call %s: %w", toolName, err)
	}
	return &callResult, nil
}
