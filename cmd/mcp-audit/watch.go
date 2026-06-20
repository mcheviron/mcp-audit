package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/mostafaelataby-cheviron/mcp-audit/internal/daemon"
)

func runWatch(args []string) {
	fs := flag.NewFlagSet("mcp-audit watch", flag.ContinueOnError)
	watchInterval := fs.Int("watch-interval", 300, "periodic re-scan interval in seconds (default 300)")
	onFinding := fs.String("on-finding", "", "shell command to run when new findings are detected")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if *watchInterval < 5 {
		fmt.Fprintf(os.Stderr, "watch-interval must be at least 5 seconds\n")
		os.Exit(2)
	}

	_ = newLogger(false, false, false)
	w := daemon.NewWatcher(time.Duration(*watchInterval)*time.Second, *onFinding)

	withSignalContext(func(ctx context.Context) error {
		return w.Watch(ctx)
	})
}
