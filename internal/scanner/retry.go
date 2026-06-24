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
	if netErr, ok := errors.AsType[net.Error](err); ok && netErr.Timeout() {
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
	timer := time.NewTimer(0)
	if !timer.Stop() {
		<-timer.C
	}
	for attempt := range maxAttempts {
		if attempt > 0 {
			timer.Reset(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
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
