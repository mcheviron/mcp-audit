package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/mcheviron/mcp-audit/internal/daemon"
)

var (
	watchInterval   int
	onFinding       string
	watchProjectDir string
	watchNoProject  bool
)

var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Watch config files and re-scan on changes",
	PreRunE: func(_ *cobra.Command, _ []string) error {
		if watchInterval < 5 {
			return fmt.Errorf("watch-interval must be at least 5 seconds")
		}
		return nil
	},
	RunE: func(_ *cobra.Command, _ []string) error {
		pDir := ""
		if !watchNoProject {
			if watchProjectDir != "" {
				pDir = watchProjectDir
			} else {
				cwd, err := os.Getwd()
				if err == nil {
					pDir = cwd
				}
			}
		}

		_ = newLogger(false, false, false)
		w := daemon.NewWatcher(time.Duration(watchInterval)*time.Second, onFinding)
		w.ProjectDir = pDir

		return withSignalContext(func(ctx context.Context) error {
			return w.Watch(ctx)
		})
	},
}

func init() {
	watchCmd.Flags().IntVar(&watchInterval, "watch-interval", 300, "periodic re-scan interval in seconds")
	watchCmd.Flags().StringVar(&onFinding, "on-finding", "", "shell command to run when new findings are detected")
	watchCmd.Flags().StringVar(&watchProjectDir, "project-dir", "", "starting directory for project-scoped discovery")
	watchCmd.Flags().BoolVar(&watchNoProject, "no-project-config", false, "disable project-scoped config discovery")
}
