package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

type sseTransport struct {
	serverURL  string
	httpClient *http.Client

	mu           sync.Mutex
	idSeq        int
	endpoint     string
	pending      map[int]chan sseResult
	connected    bool
	streamCancel context.CancelFunc
	readerDone   chan struct{}
	authToken    string
	authHeaders  map[string]string
}

type sseResult struct {
	result json.RawMessage
	rpcErr *rpcError
}

var _ Transport = (*sseTransport)(nil)

func NewSSETransport(serverURL string, timeout time.Duration) *sseTransport {
	return &sseTransport{
		serverURL: serverURL,
		httpClient: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		pending: make(map[int]chan sseResult),
	}
}

func (t *sseTransport) connect(ctx context.Context) error {
	sseURL := strings.TrimSuffix(t.serverURL, "/") + "/sse"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sseURL, nil)
	if err != nil {
		return fmt.Errorf("SSE request: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	t.setAuthHeaders(req)

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("SSE connect: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if err := resp.Body.Close(); err != nil {
			slog.Debug("close sse response body", "err", err)
		}
		return fmt.Errorf("SSE connect HTTP %d", resp.StatusCode)
	}

	reader := bufio.NewReader(resp.Body)
	endpoint, ok := readSSEEndpoint(reader, t.serverURL)
	if !ok {
		if err := resp.Body.Close(); err != nil {
			slog.Debug("close sse response body", "err", err)
		}
		return fmt.Errorf("SSE connect: no endpoint event received")
	}
	t.endpoint = endpoint

	remainder := io.MultiReader(reader, resp.Body)

	streamCtx, cancel := context.WithCancel(context.Background())
	t.streamCancel = cancel
	t.readerDone = make(chan struct{})

	go t.readEvents(streamCtx, struct {
		io.Reader
		io.Closer
	}{remainder, resp.Body})

	t.connected = true
	return nil
}

func readSSEEndpoint(reader *bufio.Reader, serverURL string) (string, bool) {
	var eventType string
	var dataLines []string

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", false
		}
		line = strings.TrimSuffix(line, "\n")
		line = strings.TrimSuffix(line, "\r")

		if line == "" {
			if len(dataLines) > 0 {
				data := strings.Join(dataLines, "\n")
				if eventType == "endpoint" {
					if !strings.HasPrefix(data, "/") {
						data = "/" + data
					}
					return serverURL + data, true
				}
				eventType = ""
				dataLines = dataLines[:0]
			}
			continue
		}

		if strings.HasPrefix(line, "event:") {
			eventType = strings.TrimSpace(line[6:])
		} else if strings.HasPrefix(line, "data:") {
			dataText := strings.TrimSpace(line[5:])
			dataLines = append(dataLines, dataText)
		}
	}
}

func (t *sseTransport) readEvents(ctx context.Context, body io.ReadCloser) {
	defer close(t.readerDone)
	defer func() {
		if err := body.Close(); err != nil {
			slog.Debug("close sse body", "err", err)
		}
	}()

	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 4096), 64*1024)

	var eventType string
	var dataLines []string

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			t.mu.Lock()
			t.connected = false
			t.mu.Unlock()
			return
		default:
		}

		line := scanner.Text()

		if line == "" {
			if len(dataLines) > 0 {
				t.handleEvent(eventType, strings.Join(dataLines, "\n"))
				eventType = ""
				dataLines = dataLines[:0]
			}
			continue
		}

		if strings.HasPrefix(line, "event:") {
			eventType = strings.TrimSpace(line[6:])
		} else if strings.HasPrefix(line, "data:") {
			dataText := strings.TrimSpace(line[5:])
			dataLines = append(dataLines, dataText)
		}
	}

	if len(dataLines) > 0 {
		t.handleEvent(eventType, strings.Join(dataLines, "\n"))
	}

	t.mu.Lock()
	t.connected = false
	t.mu.Unlock()
}

func (t *sseTransport) handleEvent(eventType, data string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if eventType == "endpoint" {
		return
	}

	var rpcResp response
	if err := json.Unmarshal([]byte(data), &rpcResp); err != nil {
		return
	}
	ch, ok := t.pending[rpcResp.ID]
	if ok {
		delete(t.pending, rpcResp.ID)
		ch <- sseResult{result: rpcResp.Result, rpcErr: rpcResp.Error}
	}
}

func (t *sseTransport) Send(ctx context.Context, method string, params any) (json.RawMessage, error) {
	t.mu.Lock()

	if !t.connected {
		if err := t.connect(ctx); err != nil {
			t.mu.Unlock()
			return nil, fmt.Errorf("SSE connect: %w", err)
		}
	}

	t.idSeq++
	id := t.idSeq
	req := request{
		JSONRPC: "2.0",
		ID:      id,
		Method:  method,
		Params:  params,
	}

	endpoint := t.endpoint
	if endpoint == "" {
		t.mu.Unlock()
		return nil, fmt.Errorf("SSE endpoint not yet discovered")
	}

	ch := make(chan sseResult, 1)
	t.pending[id] = ch
	t.mu.Unlock()

	defer func() {
		t.mu.Lock()
		delete(t.pending, id)
		t.mu.Unlock()
	}()

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	httpReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	t.setAuthHeaders(httpReq)
	postResp, err := t.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("SSE post: %w", err)
	}
	if cerr := postResp.Body.Close(); cerr != nil {
		slog.Debug("close sse post body", "err", cerr)
	}
	if postResp.StatusCode < 200 || postResp.StatusCode >= 300 {
		if postResp.StatusCode == http.StatusUnauthorized || postResp.StatusCode == http.StatusForbidden {
			return nil, fmt.Errorf("SSE post HTTP %d: %w", postResp.StatusCode, ErrAuthRequired)
		}
		return nil, fmt.Errorf("SSE post HTTP %d", postResp.StatusCode)
	}

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("SSE await response: %w", ctx.Err())
	case sr, ok := <-ch:
		if !ok {
			return nil, fmt.Errorf("SSE response channel closed")
		}
		if sr.rpcErr != nil {
			return nil, fmt.Errorf("RPC error %d: %s", sr.rpcErr.Code, sr.rpcErr.Message)
		}
		return sr.result, nil
	}
}

func (t *sseTransport) setAuthHeaders(req *http.Request) {
	if t.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+t.authToken)
	}
	for k, v := range t.authHeaders {
		req.Header.Set(k, v)
	}
}

func (t *sseTransport) SetAuthToken(token string) {
	t.authToken = token
}

func (t *sseTransport) SetAuthHeaders(headers map[string]string) {
	t.authHeaders = headers
}

func (t *sseTransport) SetCallbacks(hooks *CallbackHooks) {}

func (t *sseTransport) SetTLS(certFile, keyFile string) error {
	return nil
}

func (t *sseTransport) Close() error {
	t.mu.Lock()
	if t.streamCancel != nil {
		t.streamCancel()
	}
	done := t.readerDone
	t.mu.Unlock()

	if done != nil {
		<-done
	}

	t.mu.Lock()
	t.connected = false
	t.httpClient.CloseIdleConnections()
	t.mu.Unlock()
	return nil
}
