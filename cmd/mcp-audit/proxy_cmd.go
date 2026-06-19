package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/mostafaelataby-cheviron/mcp-audit/internal/proxy"
)

func runProxy(args []string) {
	fs := flag.NewFlagSet("mcp-audit proxy", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8080", "address to listen on")
	target := fs.String("target", "", "target MCP server URL (required)")
	blockCritical := fs.Bool("block-critical", false, "block responses containing CRITICAL findings")
	maxResponse := fs.Int("max-response", 65536, "max response body size in bytes")
	verbose := fs.Bool("verbose", false, "enable debug logging")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	if *target == "" {
		fmt.Fprintf(os.Stderr, "--target is required for proxy mode\n")
		os.Exit(2)
	}
	_ = newLogger(*verbose, false, false)
	cfg := proxy.Config{
		ListenAddr:      *listen,
		TargetURL:       *target,
		BlockCritical:   *blockCritical,
		MaxResponseSize: int64(*maxResponse),
	}
	p := proxy.New(cfg)
	if err := p.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "proxy error: %v\n", err)
		os.Exit(1)
	}
}
