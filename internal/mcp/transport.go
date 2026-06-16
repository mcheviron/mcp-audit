package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client interface {
	Initialize(ctx context.Context) (*InitializeResult, error)
	ListTools(ctx context.Context) (*ListToolsResult, error)
	CallTool(ctx context.Context, toolName string, args map[string]any) (*CallToolResult, error)
}

type httpClient struct {
	httpClient *http.Client
	endpoint   string
	idSeq      int
}

var _ Client = (*httpClient)(nil)

func NewClient(endpoint string, timeout time.Duration) Client {
	return &httpClient{
		httpClient: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		endpoint: endpoint,
		idSeq:    0,
	}
}

func (c *httpClient) nextID() int {
	c.idSeq++
	return c.idSeq
}

func (c *httpClient) Initialize(ctx context.Context) (*InitializeResult, error) {
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

	var result InitializeResult
	if err := c.call(ctx, "initialize", params, &result); err != nil {
		return nil, fmt.Errorf("initialize: %w", err)
	}
	return &result, nil
}

func (c *httpClient) ListTools(ctx context.Context) (*ListToolsResult, error) {
	var result ListToolsResult
	if err := c.call(ctx, "tools/list", nil, &result); err != nil {
		return nil, fmt.Errorf("tools/list: %w", err)
	}
	return &result, nil
}

func (c *httpClient) CallTool(ctx context.Context, toolName string, args map[string]any) (*CallToolResult, error) {
	params := CallToolParams{
		Name:      toolName,
		Arguments: args,
	}

	var result CallToolResult
	if err := c.call(ctx, "tools/call", params, &result); err != nil {
		return nil, fmt.Errorf("tools/call %s: %w", toolName, err)
	}
	return &result, nil
}

func (c *httpClient) call(ctx context.Context, method string, params any, result any) error {
	req := request{
		JSONRPC: "2.0",
		ID:      c.nextID(),
		Method:  method,
		Params:  params,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	limited := io.LimitReader(resp.Body, 4096)
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, limited); err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, buf.String())
	}

	var rpcResp response
	if err := json.Unmarshal(buf.Bytes(), &rpcResp); err != nil {
		return fmt.Errorf("unmarshal response: %w", err)
	}

	if rpcResp.Error != nil {
		return fmt.Errorf("RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	if result != nil && rpcResp.Result != nil {
		if err := json.Unmarshal(rpcResp.Result, result); err != nil {
			return fmt.Errorf("unmarshal result: %w", err)
		}
	}

	return nil
}
