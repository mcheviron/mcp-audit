package scanner

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestIsTransientTimeoutError(t *testing.T) {
	err := &net.OpError{Err: &timeoutError{}, Op: "dial"}
	if !isTransient(err) {
		t.Error("timeout errors should be transient")
	}
}

type timeoutError struct{}

func (e *timeoutError) Error() string   { return "timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

func TestIsTransientConnectionRefused(t *testing.T) {
	err := errors.New("dial tcp 127.0.0.1:8080: connect: connection refused")
	if !isTransient(err) {
		t.Error("connection refused should be transient")
	}
}

func TestIsTransient503(t *testing.T) {
	err := errors.New("HTTP 503 Service Unavailable")
	if !isTransient(err) {
		t.Error("503 should be transient")
	}
}

func TestIsTransientPermanent400(t *testing.T) {
	err := errors.New("HTTP 400 Bad Request")
	if isTransient(err) {
		t.Error("400 should not be transient")
	}
}

func TestIsTransientNil(t *testing.T) {
	if isTransient(nil) {
		t.Error("nil error should not be transient")
	}
}

func TestRetrySuccess(t *testing.T) {
	attempts := 0
	err := retry(context.Background(), 3, func() error {
		attempts++
		if attempts < 2 {
			return errors.New("connection refused")
		}
		return nil
	})
	if err != nil {
		t.Errorf("retry should succeed: %v", err)
	}
	if attempts != 2 {
		t.Errorf("expected 2 attempts, got %d", attempts)
	}
}

func TestRetryPermanentFailure(t *testing.T) {
	attempts := 0
	err := retry(context.Background(), 3, func() error {
		attempts++
		return errors.New("HTTP 400 Bad Request")
	})
	if err == nil {
		t.Error("permanent failure should not retry")
	}
	if attempts != 1 {
		t.Errorf("expected 1 attempt, got %d", attempts)
	}
}

func TestRetryContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := retry(ctx, 3, func() error {
		return errors.New("connection refused")
	})
	if err == nil {
		t.Error("cancelled context should return error")
	}
}

func TestRetryExhausted(t *testing.T) {
	attempts := 0
	err := retry(context.Background(), 3, func() error {
		attempts++
		return errors.New("connection refused")
	})
	if err == nil {
		t.Error("exhausted retries should return last error")
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestRetryBackoff(t *testing.T) {
	start := time.Now()
	_ = retry(context.Background(), 3, func() error {
		return errors.New("connection refused")
	})
	elapsed := time.Since(start)
	if elapsed < 300*time.Millisecond {
		t.Errorf("expected at least ~300ms backoff, got %v", elapsed)
	}
}
