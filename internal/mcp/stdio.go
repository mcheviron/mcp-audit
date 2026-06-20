package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type stdioTransport struct {
	command string
	args    []string

	mu      sync.Mutex
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	stdout  *bufio.Scanner
	idSeq   int
	running bool
}

var _ Transport = (*stdioTransport)(nil)

func NewStdioTransport(command string, args []string, _ time.Duration) *stdioTransport {
	return &stdioTransport{
		command: command,
		args:    args,
	}
}

var shellCommands = map[string]bool{
	"bash": true, "sh": true, "zsh": true, "dash": true,
	"fish": true, "csh": true, "tcsh": true, "ksh": true,
}

func isShell(cmd string) bool {
	resolved := cmd
	if lp, err := exec.LookPath(cmd); err == nil {
		if eval, err := filepath.EvalSymlinks(lp); err == nil {
			resolved = eval
		} else {
			resolved = lp
		}
	}
	return shellCommands[filepath.Base(resolved)]
}

func (t *stdioTransport) start(ctx context.Context) error {
	if t.running {
		return nil
	}

	if isShell(t.command) {
		return fmt.Errorf("stdio: shell interpreters are not allowed for security reasons (got %q)", t.command)
	}

	t.cmd = exec.CommandContext(context.Background(), t.command, t.args...) //nolint:gosec
	t.cmd.Cancel = func() error {
		if t.cmd.Process != nil {
			return t.cmd.Process.Signal(syscall.SIGKILL)
		}
		return nil
	}
	t.cmd.WaitDelay = 2 * time.Second

	var err error
	t.stdin, err = t.cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}

	stdoutPipe, err := t.cmd.StdoutPipe()
	if err != nil {
		if err := t.stdin.Close(); err != nil {
			slog.Debug("close stdin", "err", err)
		}
		return fmt.Errorf("stdout pipe: %w", err)
	}

	if err := t.cmd.Start(); err != nil {
		if err := t.stdin.Close(); err != nil {
			slog.Debug("close stdin", "err", err)
		}
		if err := stdoutPipe.Close(); err != nil {
			slog.Debug("close stdout pipe", "err", err)
		}
		return fmt.Errorf("start command: %w", err)
	}

	t.stdout = bufio.NewScanner(stdoutPipe)
	t.stdout.Buffer(make([]byte, 0, 4096), 64*1024)
	t.running = true
	return nil
}

func (t *stdioTransport) kill() {
	if t.cmd != nil && t.cmd.Process != nil {
		_ = t.cmd.Process.Kill()
		if err := t.cmd.Wait(); err != nil {
			slog.Debug("wait stdio cmd", "err", err)
		}
	}
	t.running = false
	t.cmd = nil
	t.stdin = nil
	t.stdout = nil
}

func (t *stdioTransport) Send(ctx context.Context, method string, params any) (json.RawMessage, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.running {
		if err := t.start(ctx); err != nil {
			return nil, fmt.Errorf("start stdio: %w", err)
		}
	}

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

	body = append(body, '\n')

	if err := t.writeLine(ctx, body); err != nil {
		return nil, err
	}

	respBytes, err := t.readLine(ctx)
	if err != nil {
		return nil, err
	}

	var rpcResp response
	if err := json.Unmarshal(respBytes, &rpcResp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	return rpcResp.Result, nil
}

func (t *stdioTransport) writeLine(ctx context.Context, line []byte) error {
	stdin := t.stdin
	writeDone := make(chan error, 1)
	go func() {
		_, err := stdin.Write(line)
		writeDone <- err
	}()

	select {
	case <-ctx.Done():
		t.kill()
		return fmt.Errorf("stdio write cancelled: %w", ctx.Err())
	case err := <-writeDone:
		if err != nil {
			t.kill()
			return fmt.Errorf("stdio write: %w", err)
		}
		return nil
	}
}

func (t *stdioTransport) readLine(ctx context.Context) ([]byte, error) {
	stdout := t.stdout
	readDone := make(chan struct{})
	var scanOK bool
	go func() {
		scanOK = stdout.Scan()
		close(readDone)
	}()

	select {
	case <-ctx.Done():
		t.kill()
		return nil, fmt.Errorf("stdio read cancelled: %w", ctx.Err())
	case <-readDone:
	}

	if !scanOK {
		err := stdout.Err()
		t.kill()
		if err != nil {
			return nil, fmt.Errorf("stdio read: %w", err)
		}
		return nil, fmt.Errorf("stdio read: unexpected EOF")
	}

	return stdout.Bytes(), nil
}

func (t *stdioTransport) SetCallbacks(hooks *CallbackHooks)        {}
func (t *stdioTransport) SetAuthToken(token string)                {}
func (t *stdioTransport) SetAuthHeaders(headers map[string]string) {}
func (t *stdioTransport) SetTLS(certFile, keyFile string) error    { return nil }

func (t *stdioTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.running {
		t.kill()
	}
	return nil
}
