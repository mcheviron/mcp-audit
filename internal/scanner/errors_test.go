package scanner

import (
	"errors"
	"testing"
)

func TestProbeErrorErrorAndUnwrap(t *testing.T) {
	inner := errors.New("connection timeout")
	e := &ProbeError{Target: "http://127.0.0.1/", Server: "test-srv", Err: inner}

	if e.Error() != `probe http://127.0.0.1/ on test-srv: connection timeout` {
		t.Errorf("unexpected error string: %s", e.Error())
	}
	if !errors.Is(e, inner) {
		t.Error("errors.Is should find inner error")
	}
}

func TestConfigErrorErrorAndUnwrap(t *testing.T) {
	inner := errors.New("invalid JSON")
	e := &ConfigError{Path: "/tmp/config.json", Err: inner}

	if e.Error() != `config /tmp/config.json: invalid JSON` {
		t.Errorf("unexpected error string: %s", e.Error())
	}
	if !errors.Is(e, inner) {
		t.Error("errors.Is should find inner error")
	}
}

func TestTransportErrorErrorAndUnwrap(t *testing.T) {
	inner := errors.New("TLS handshake failed")
	e := &TransportError{Transport: "http", Server: "srv1", Err: inner}

	if e.Error() != `transport http on srv1: TLS handshake failed` {
		t.Errorf("unexpected error string: %s", e.Error())
	}
	if !errors.Is(e, inner) {
		t.Error("errors.Is should find inner error")
	}
}

func TestProbeErrorUnwrapNil(t *testing.T) {
	e := &ProbeError{Target: "t", Server: "s", Err: nil}
	if e.Unwrap() != nil {
		t.Error("Unwrap should return nil")
	}
}
