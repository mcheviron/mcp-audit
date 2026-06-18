package scanner

import (
	"errors"
	"fmt"
)

var ErrProbeTimeout = errors.New("probe timeout")
var ErrConfigParse = errors.New("config parse error")

type ProbeError struct {
	Target string
	Server string
	Err    error
}

func (e *ProbeError) Error() string {
	return fmt.Sprintf("probe %s on %s: %v", e.Target, e.Server, e.Err)
}

func (e *ProbeError) Unwrap() error {
	return e.Err
}

type ConfigError struct {
	Path string
	Err  error
}

func (e *ConfigError) Error() string {
	return fmt.Sprintf("config %s: %v", e.Path, e.Err)
}

func (e *ConfigError) Unwrap() error {
	return e.Err
}

type TransportError struct {
	Transport string
	Server    string
	Err       error
}

func (e *TransportError) Error() string {
	return fmt.Sprintf("transport %s on %s: %v", e.Transport, e.Server, e.Err)
}

func (e *TransportError) Unwrap() error {
	return e.Err
}
