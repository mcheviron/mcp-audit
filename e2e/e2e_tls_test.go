package e2e_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestE2E_Proxy_UpstreamTLS_DefaultTransport(t *testing.T) {
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

	resp, err := http.Post("http://"+addr, "application/json",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}`))
	if err != nil {
		cmd.Process.Kill()
		t.Fatalf("proxy request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	cmd.Process.Signal(syscall.SIGTERM)
	cmd.Wait()
}

func TestE2E_Proxy_UpstreamTLS_CAConfigured(t *testing.T) {
	bin := buildBinary(t)

	certDir := t.TempDir()
	certFile := filepath.Join(certDir, "ca.pem")
	keyFile := filepath.Join(certDir, "ca-key.pem")

	caCert, caKey := generateCA(t)
	writeCertAndKey(t, certFile, keyFile, caCert, caKey)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	cmd := exec.Command(bin, "proxy", "--target", "http://127.0.0.1:1", "--listen", addr,
		"--upstream-ca-cert", certFile)
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start proxy with CA: %v", err)
	}

	if !waitForListen(t, addr, 3*time.Second) {
		cmd.Process.Kill()
		t.Fatal("proxy did not start listening within 3 seconds")
	}

	cmd.Process.Signal(syscall.SIGTERM)
	err = cmd.Wait()
	if err != nil {
		t.Logf("proxy with CA exit: %v", err)
	}
}

func TestE2E_Proxy_UpstreamTLS_mTLSConfigured(t *testing.T) {
	bin := buildBinary(t)

	certDir := t.TempDir()
	certFile := filepath.Join(certDir, "client.pem")
	keyFile := filepath.Join(certDir, "client-key.pem")

	caCert, caKey := generateCA(t)
	clientCert, clientKey := generateClientCert(t, caCert, caKey)
	writeCertAndKey(t, certFile, keyFile, clientCert, clientKey)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	cmd := exec.Command(bin, "proxy", "--target", "http://127.0.0.1:1", "--listen", addr,
		"--upstream-cert", certFile, "--upstream-key", keyFile)
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start proxy with mTLS: %v", err)
	}

	if !waitForListen(t, addr, 3*time.Second) {
		cmd.Process.Kill()
		t.Fatal("proxy did not start listening within 3 seconds")
	}

	cmd.Process.Signal(syscall.SIGTERM)
	err = cmd.Wait()
	if err != nil {
		t.Logf("proxy with mTLS exit: %v\nstderr:\n%s", err, stderr.String())
	}
}

func generateCA(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func generateClientCert(t *testing.T, caCertPEM, caKeyPEM []byte) ([]byte, []byte) {
	t.Helper()
	caCertBlock, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	caKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		t.Fatalf("parse CA key: %v", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Client"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func writeCertAndKey(t *testing.T, certPath, keyPath string, certPEM, keyPEM []byte) {
	t.Helper()
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
}
