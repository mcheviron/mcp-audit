package scanner

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"
)

func isTransient(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	errStr := err.Error()
	if strings.Contains(errStr, "connection refused") {
		return true
	}
	if strings.Contains(errStr, "503") || strings.Contains(errStr, "Service Unavailable") {
		return true
	}
	return false
}

func retry(ctx context.Context, maxAttempts int, fn func() error) error {
	var lastErr error
	backoff := 100 * time.Millisecond
	for attempt := range maxAttempts {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
				backoff *= 2
			}
		}
		lastErr = fn()
		if lastErr == nil {
			return nil
		}
		if !isTransient(lastErr) {
			return lastErr
		}
	}
	return lastErr
}
