package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func withSignalContext(fn func(ctx context.Context) error) error {
	ctx, cancel := context.WithCancel(context.Background())
	sigCtx, _ := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	if err := fn(sigCtx); err != nil {
		cancel()
		return err
	}
	cancel()
	return nil
}
