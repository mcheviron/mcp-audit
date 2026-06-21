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
	projectDir := fs.String("project-dir", "", "starting directory for project-scoped discovery")
	noProjectConfig := fs.Bool("no-project-config", false, "disable project-scoped config discovery")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if *watchInterval < 5 {
		fmt.Fprintf(os.Stderr, "watch-interval must be at least 5 seconds\n")
		os.Exit(2)
	}

	pDir := ""
	if !*noProjectConfig {
		if *projectDir != "" {
			pDir = *projectDir
		} else {
			cwd, err := os.Getwd()
			if err == nil {
				pDir = cwd
			}
		}
	}

	_ = newLogger(false, false, false)
	w := daemon.NewWatcher(time.Duration(*watchInterval)*time.Second, *onFinding)
	w.ProjectDir = pDir

	withSignalContext(func(ctx context.Context) error {
		return w.Watch(ctx)
	})
}
