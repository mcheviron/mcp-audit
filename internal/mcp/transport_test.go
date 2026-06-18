package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestInitialize(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		var req request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Method != "initialize" {
			t.Errorf("expected initialize, got %s", req.Method)
		}

		resp := response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  json.RawMessage(`{"protocolVersion":"2024-11-05","capabilities":{"tools":{"listChanged":true}},"serverInfo":{"name":"test","version":"1.0"}}`),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := NewClient(NewHTTPTransport(srv.URL, 5*time.Second, 65536))
	result, err := client.Initialize(context.Background())
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if result.ProtocolVersion != "2024-11-05" {
		t.Errorf("expected 2024-11-05, got %s", result.ProtocolVersion)
	}
	if result.ServerInfo.Name != "test" {
		t.Errorf("expected test, got %s", result.ServerInfo.Name)
	}
}

func TestListTools(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req request
		json.NewDecoder(r.Body).Decode(&req)

		var result json.RawMessage
		switch req.Method {
		case "initialize":
			result = json.RawMessage(
				`{"protocolVersion":"2024-11-05","capabilities":{},` +
					`"serverInfo":{"name":"test","version":"1.0"}}`)
		case "tools/list":
			result = json.RawMessage(`{"tools":[{"name":"fetch","description":"Fetch a URL","inputSchema":{}}]}`)
		}

		resp := response{JSONRPC: "2.0", ID: req.ID, Result: result}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := NewClient(NewHTTPTransport(srv.URL, 5*time.Second, 65536))
	_, err := client.Initialize(context.Background())
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	tools, err := client.ListTools(context.Background())
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(tools.Tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools.Tools))
	}
	if tools.Tools[0].Name != "fetch" {
		t.Errorf("expected fetch, got %s", tools.Tools[0].Name)
	}
}

func TestCallTool(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req request
		json.NewDecoder(r.Body).Decode(&req)

		var result json.RawMessage
		switch req.Method {
		case "initialize":
			result = json.RawMessage(
				`{"protocolVersion":"2024-11-05","capabilities":{},` +
					`"serverInfo":{"name":"test","version":"1.0"}}`)
		case "tools/call":
			result = json.RawMessage(`{"content":[{"type":"text","text":"response text"}],"isError":false}`)
		}

		resp := response{JSONRPC: "2.0", ID: req.ID, Result: result}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := NewClient(NewHTTPTransport(srv.URL, 5*time.Second, 65536))
	_, err := client.Initialize(context.Background())
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	callResult, err := client.CallTool(context.Background(), "fetch", map[string]any{"url": "http://example.com"})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if len(callResult.Content) != 1 {
		t.Fatalf("expected 1 content, got %d", len(callResult.Content))
	}
	if callResult.Content[0].Text != "response text" {
		t.Errorf("expected 'response text', got %s", callResult.Content[0].Text)
	}
}

func TestInitializeTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	defer srv.Close()

	client := NewClient(NewHTTPTransport(srv.URL, 50*time.Millisecond, 65536))
	_, err := client.Initialize(context.Background())
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestRPCError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req request
		json.NewDecoder(r.Body).Decode(&req)

		resp := response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &rpcError{Code: -32600, Message: "Invalid Request"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := NewClient(NewHTTPTransport(srv.URL, 5*time.Second, 65536))
	_, err := client.Initialize(context.Background())
	if err == nil {
		t.Fatal("expected RPC error")
	}
}

func TestStdioTransport(t *testing.T) {
	if os.Getenv("SKIP_STDIO") != "" {
		t.Skip("skipping stdio test")
	}

	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not found")
	}

	pyScript := `import sys,json;line=sys.stdin.readline()` +
		`;print(json.dumps({"jsonrpc":"2.0","id":1,` +
		`"result":{"serverInfo":{"name":"echo","version":"1.0"},` +
		`"protocolVersion":"2024-11-05","capabilities":{}}}))`
	tr := NewStdioTransport("python3", []string{"-c", pyScript}, 5*time.Second)
	defer tr.Close()

	result, err := tr.Send(context.Background(), "initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]string{"name": "test", "version": "1.0"},
	})
	if err != nil {
		t.Fatalf("stdio send: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestStdioTransportRestart(t *testing.T) {
	if os.Getenv("SKIP_STDIO") != "" {
		t.Skip("skipping stdio test")
	}

	if _, err := exec.LookPath("sleep"); err != nil {
		t.Skip("sleep not found")
	}

	tr := NewStdioTransport("sleep", []string{"10"}, 5*time.Second)
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := tr.Send(ctx, "initialize", nil)
	if err == nil {
		t.Fatal("expected timeout/cancellation error")
	}
	if tr.running {
		t.Error("expected process to be killed after timeout")
	}
}

func TestHTTPTransportSessionID(t *testing.T) {
	var capturedSessionID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sid := r.Header.Get("Mcp-Session-Id"); sid != "" {
			capturedSessionID = sid
		}
		if r.URL.Path == "/" {
			w.Header().Set("Mcp-Session-Id", "session-abc-123")
		}

		var req request
		json.NewDecoder(r.Body).Decode(&req)
		resp := response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  json.RawMessage(`{}`),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	tr := NewHTTPTransport(srv.URL, 5*time.Second, 65536)

	_, err := tr.Send(context.Background(), "initialize", nil)
	if err != nil {
		t.Fatalf("first send: %v", err)
	}

	_, err = tr.Send(context.Background(), "tools/list", nil)
	if err != nil {
		t.Fatalf("second send: %v", err)
	}

	if capturedSessionID != "session-abc-123" {
		t.Errorf("expected session ID session-abc-123 in second request, got %q", capturedSessionID)
	}
}

func TestHTTPTransportAuthHeader(t *testing.T) {
	var capturedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")

		var req request
		json.NewDecoder(r.Body).Decode(&req)
		resp := response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  json.RawMessage(`{}`),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	tr := NewHTTPTransport(srv.URL, 5*time.Second, 65536)
	tr.SetAuthToken("test-token")
	tr.SetAuthHeaders(map[string]string{"X-API-Key": "key-123"})

	_, err := tr.Send(context.Background(), "initialize", nil)
	if err != nil {
		t.Fatalf("send: %v", err)
	}

	if capturedAuth != "Bearer test-token" {
		t.Errorf("expected Bearer test-token, got %q", capturedAuth)
	}
}

func TestSSETransport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/sse") {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			flusher, ok := w.(http.Flusher)
			if !ok {
				t.Error("expected flusher")
				return
			}

			fmt.Fprintf(w, "event: endpoint\ndata: /message\n\n")
			flusher.Flush()

			fmt.Fprint(w, "event: message\n"+
				`data: {"jsonrpc":"2.0","id":1,"result":{"serverInfo":`+
				`{"name":"sse-test","version":"1.0"},`+
				`"protocolVersion":"2024-11-05","capabilities":{}}}`+"\n\n")
			flusher.Flush()
		} else {
			var req request
			json.NewDecoder(r.Body).Decode(&req)
			resp := response{JSONRPC: "2.0", ID: req.ID, Result: json.RawMessage(`{}`)}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}
	}))
	defer srv.Close()

	tr := NewSSETransport(srv.URL, 5*time.Second)
	defer tr.Close()

	result, err := tr.Send(context.Background(), "initialize", nil)
	if err != nil {
		t.Fatalf("SSE send: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	var initResult InitializeResult
	if err := json.Unmarshal(result, &initResult); err != nil {
		t.Fatalf("unmarshal initialize result: %v", err)
	}
	if initResult.ServerInfo.Name != "sse-test" {
		t.Errorf("expected sse-test server, got %q", initResult.ServerInfo.Name)
	}
}

func TestNewClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req request
		json.NewDecoder(r.Body).Decode(&req)

		var result json.RawMessage
		switch req.Method {
		case "initialize":
			result = json.RawMessage(
				`{"protocolVersion":"2024-11-05","capabilities":{},` +
					`"serverInfo":{"name":"test","version":"1.0"}}`)
		}

		resp := response{JSONRPC: "2.0", ID: req.ID, Result: result}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	tr := NewHTTPTransport(srv.URL, 5*time.Second, 65536)
	client := NewClient(tr)

	result, err := client.Initialize(context.Background())
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if result.ServerInfo.Name != "test" {
		t.Errorf("expected test server, got %q", result.ServerInfo.Name)
	}
}

func TestTransportInterface(t *testing.T) {
	var _ Transport = (*HTTPTransport)(nil)
	var _ Transport = (*stdioTransport)(nil)
	var _ Transport = (*sseTransport)(nil)

	var _ Client = (*mcpClient)(nil)
}
