package main

import (
	"context"
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
	upstreamCACert := fs.String("upstream-ca-cert", "", "CA certificate for upstream TLS verification")
	upstreamCert := fs.String("upstream-cert", "", "client certificate for upstream mTLS")
	upstreamKey := fs.String("upstream-key", "", "client key for upstream mTLS")
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
		UpstreamCACert:  *upstreamCACert,
		UpstreamCert:    *upstreamCert,
		UpstreamKey:     *upstreamKey,
	}
	p := proxy.New(cfg)

	withSignalContext(func(ctx context.Context) error {
		return p.Start(ctx)
	})
}
