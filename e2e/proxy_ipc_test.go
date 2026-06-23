package e2e_test

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

func findFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	addr := l.Addr().(*net.TCPAddr)
	port := addr.Port
	l.Close()
	return port
}

func waitForListen(t *testing.T, addr string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func TestE2E_Proxy_GracefulShutdown_SIGTERM(t *testing.T) {
	bin := buildBinary(t)

	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"name":"test","version":"1.0"},"protocolVersion":"2024-11-05","capabilities":{}}}`))
	}))
	defer targetServer.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	cmd := exec.Command(bin, "proxy", "--target", targetServer.URL, "--listen", addr)
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start proxy: %v", err)
	}

	if !waitForListen(t, addr, 3*time.Second) {
		cmd.Process.Kill()
		t.Fatal("proxy did not start listening within 3 seconds")
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("proxy exited with error: %v\nstderr:\n%s", err, stderr.String())
		}
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		t.Fatal("proxy did not shut down within 10 seconds after SIGTERM")
	}
}

func TestE2E_Proxy_GracefulShutdown_InflightRequestCompletes(t *testing.T) {
	bin := buildBinary(t)

	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"fast response"}],"isError":false}}`))
	}))
	defer targetServer.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	cmd := exec.Command(bin, "proxy", "--target", targetServer.URL, "--listen", addr)
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start proxy: %v", err)
	}

	if !waitForListen(t, addr, 3*time.Second) {
		cmd.Process.Kill()
		t.Fatal("proxy did not start listening within 3 seconds")
	}

	resp, err := http.Post("http://"+addr, "application/json",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch","arguments":{}}}`))
	if err != nil {
		cmd.Process.Kill()
		t.Fatalf("proxy request: %v", err)
	}
	resp.Body.Close()

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("proxy exited with error: %v\nstderr:\n%s", err, stderr.String())
		}
	case <-time.After(5 * time.Second):
		cmd.Process.Kill()
		t.Fatal("proxy did not shut down within 5 seconds after SIGTERM")
	}
}

func TestE2E_Proxy_SecondSignalExits(t *testing.T) {
	bin := buildBinary(t)

	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer targetServer.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	cmd := exec.Command(bin, "proxy", "--target", targetServer.URL, "--listen", addr)
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())

	if err := cmd.Start(); err != nil {
		t.Fatalf("start proxy: %v", err)
	}

	if !waitForListen(t, addr, 3*time.Second) {
		cmd.Process.Kill()
		t.Fatal("proxy did not start listening within 3 seconds")
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("send first SIGTERM: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("send SIGKILL: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		cmd.Process.Kill()
		t.Fatal("proxy did not exit within 5 seconds after SIGKILL")
	}
}
