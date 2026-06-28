package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"
)

func startCallbackListener(port int) (*CallbackListener, error) {
	cl := &CallbackListener{
		Callback: make(chan string, 50),
		done:     make(chan struct{}),
	}

	lc := net.ListenConfig{}
	lis, err := lc.Listen(context.Background(), "tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, fmt.Errorf("callback listener bind failed on port %d: %w", port, err)
	}

	cl.Port = lis.Addr().(*net.TCPAddr).Port

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		source := r.RemoteAddr
		ua := r.Header.Get("User-Agent")
		select {
		case cl.Callback <- fmt.Sprintf("%s (ua: %s)", source, ua):
		default:
		}
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("ok")); err != nil {
			slog.Debug("callback write response", "err", err)
		}
	})

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.Serve(lis); err != nil && err != http.ErrServerClosed {
			slog.Debug("callback server serve", "err", err)
		}
	}()

	go func() {
		<-cl.done
		if err := srv.Close(); err != nil {
			slog.Debug("callback server close", "err", err)
		}
	}()

	return cl, nil
}

func (cl *CallbackListener) stopCallbackListener() {
	close(cl.done)
}

func (cl *CallbackListener) drainCallbacks(timeout time.Duration) {
	if cl == nil {
		return
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case <-cl.Callback:
		case <-timer.C:
			return
		}
	}
}

func (cl *CallbackListener) collectCallbackResults(srvName, configPath string) []Result {
	if cl == nil {
		return nil
	}
	cl.mu.Lock()
	defer cl.mu.Unlock()
	var results []Result
	for {
		select {
		case src := <-cl.Callback:
			results = append(results, Result{
				Severity:   SevCritical,
				Server:     srvName,
				Type:       FindingTypeDynamic,
				Finding:    fmt.Sprintf("blind SSRF confirmed: server made outbound request to callback listener from %s", src),
				ConfigPath: configPath,
			})
		default:
			return results
		}
	}
}
