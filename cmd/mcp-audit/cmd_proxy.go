package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/mcheviron/mcp-audit/internal/proxy"
)

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Start a transparent MCP proxy",
	RunE: func(cmd *cobra.Command, _ []string) error {
		target, _ := cmd.Flags().GetString("target")
		listen, _ := cmd.Flags().GetString("listen")
		blockCritical, _ := cmd.Flags().GetBool("block-critical")
		maxResponse, _ := cmd.Flags().GetInt("max-response")
		verbose, _ := cmd.Flags().GetBool("verbose")
		upstreamCACert, _ := cmd.Flags().GetString("upstream-ca-cert")
		upstreamCert, _ := cmd.Flags().GetString("upstream-cert")
		upstreamKey, _ := cmd.Flags().GetString("upstream-key")
		policyPath, _ := cmd.Flags().GetString("policy")
		defaultDeny, _ := cmd.Flags().GetBool("default-deny")

		_ = newLogger(verbose, false, false)
		cfg := proxy.Config{
			ListenAddr:      listen,
			TargetURL:       target,
			BlockCritical:   blockCritical,
			MaxResponseSize: int64(maxResponse),
			UpstreamCACert:  upstreamCACert,
			UpstreamCert:    upstreamCert,
			UpstreamKey:     upstreamKey,
			PolicyPath:      policyPath,
			DefaultDeny:     defaultDeny,
		}
		p := proxy.New(cfg)

		return withSignalContext(func(ctx context.Context) error {
			return p.Start(ctx)
		})
	},
}

var proxyPolicyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage proxy policies",
}

var proxyPolicyValidateCmd = &cobra.Command{
	Use:   "validate [file]",
	Short: "Validate a proxy policy YAML file",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		path := args[0]
		cfg, err := proxy.LoadPolicy(path)
		if err != nil {
			return &exitError{code: 1, err: fmt.Errorf("policy validation failed: %w", err)}
		}
		fmt.Printf("Policy valid: %d rules loaded from %s\n", len(cfg.Rules), path)
		return nil
	},
}

func init() {
	proxyCmd.Flags().String("listen", "127.0.0.1:8080", "address to listen on")
	proxyCmd.Flags().String("target", "", "target MCP server URL (required)")
	_ = proxyCmd.MarkFlagRequired("target")
	proxyCmd.Flags().Bool("block-critical", false, "block responses containing CRITICAL findings")
	proxyCmd.Flags().Int("max-response", 65536, "max response body size in bytes")
	proxyCmd.Flags().Bool("verbose", false, "enable debug logging")
	proxyCmd.Flags().String("upstream-ca-cert", "", "CA certificate for upstream TLS verification")
	proxyCmd.Flags().String("upstream-cert", "", "client certificate for upstream mTLS")
	proxyCmd.Flags().String("upstream-key", "", "client key for upstream mTLS")
	proxyCmd.Flags().String("policy", "", "path to policy YAML file")
	proxyCmd.Flags().Bool("default-deny", false, "deny requests that don't match any allow rule")

	proxyPolicyCmd.AddCommand(proxyPolicyValidateCmd)
	proxyCmd.AddCommand(proxyPolicyCmd)
}
