package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/mostafaelataby-cheviron/mcp-audit/internal/report"
	"github.com/mostafaelataby-cheviron/mcp-audit/internal/scanner"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(0)
	}

	cmd := os.Args[1]
	switch cmd {
	case "scan":
		runStaticAction("scan", os.Args[2:])
	case "static":
		runStaticAction("static", os.Args[2:])
	case "probe":
		runProbe(os.Args[2:])
	case "version":
		fmt.Println("mcp-audit v0.1.0")
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "mcp-audit: unknown command %q\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func splitKeyValue(s string) map[string]string {
	if s == "" {
		return nil
	}
	var m map[string]string
	for pair := range strings.SplitSeq(s, ",") {
		pair = strings.TrimSpace(pair)
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 {
			if m == nil {
				m = make(map[string]string)
			}
			m[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	return m
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

type flags struct {
	format            string
	dryRun            bool
	allowHosts        string
	blockHosts        string
	targets           string
	trustConfig       string
	transport         string
	authToken         string
	authHeaders       string
	tlsCert           string
	tlsKey            string
	noToolAnalysis    bool
	snapshotDir       string
	noSnapshot        bool
	noTrustOnFirstUse bool
	noSecretScan      bool
	probeDepth        string
	callbackPort      int
	targetsFile       string
	maxResponse       int
}

func parseFlags(args []string) flags {
	var f flags
	fs := flag.NewFlagSet("mcp-audit", flag.ContinueOnError)
	fs.StringVar(&f.format, "format", "table", "output format: table, json, sarif")
	fs.BoolVar(&f.dryRun, "dry-run", false, "print what would be probed without making requests")
	fs.StringVar(&f.allowHosts, "allow-hosts", "", "comma-separated hosts/IPs to allow for probing")
	fs.StringVar(&f.blockHosts, "block-hosts", "", "comma-separated hosts/IPs to block from probing")
	fs.StringVar(&f.targets, "targets", "", "comma-separated probe target URLs (overrides defaults)")
	fs.StringVar(&f.trustConfig, "trust-config", "",
		"path to trust config JSON (default ~/.config/mcp-audit/trust.json)")
	fs.StringVar(&f.transport, "transport", "", "force transport type: stdio, sse, http")
	fs.StringVar(&f.authToken, "auth-token", "", "Bearer token for MCP server authentication")
	fs.StringVar(&f.authHeaders, "auth-headers", "", "comma-separated key=value auth headers")
	fs.StringVar(&f.tlsCert, "tls-cert", "", "TLS client certificate file for mTLS")
	fs.StringVar(&f.tlsKey, "tls-key", "", "TLS client key file for mTLS")
	fs.BoolVar(&f.noToolAnalysis, "no-tool-analysis", false, "disable tool description and schema security analysis")
	fs.StringVar(&f.snapshotDir, "snapshot-dir", "", "override snapshot directory (default ~/.config/mcp-audit/snapshots)")
	fs.BoolVar(&f.noSnapshot, "no-snapshot", false, "disable snapshot persistence and drift detection")
	fs.BoolVar(&f.noTrustOnFirstUse, "no-trust-on-first-use", false, "require pre-populated pinned hashes for first scan")
	fs.BoolVar(&f.noSecretScan, "no-secret-scan", false, "disable credential and secret scanning of config files")
	fs.StringVar(&f.probeDepth, "probe-depth", "basic", "probe depth: basic, extended, full")
	fs.IntVar(&f.callbackPort, "callback-port", 0, "callback listener port (0=random)")
	fs.StringVar(&f.targetsFile, "targets-file", "", "file with probe target URLs (one per line)")
	fs.IntVar(&f.maxResponse, "max-response", 65536, "max response body size in bytes (max 1048576)")
	fs.SetOutput(os.Stderr)
	_ = fs.Parse(args)
	return f
}

func runStaticAction(action string, args []string) {
	f := parseFlags(args)

	s := scanner.NewScanner()
	if err := s.SetTrustConfig(f.trustConfig); err != nil {
		if f.trustConfig != "" {
			fmt.Fprintf(os.Stderr, "%s: trust config error: %v\n", action, err)
			os.Exit(2)
		}
	}
	s.NoSecretScan = f.noSecretScan

	results, err := s.Static()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", action, err)
		os.Exit(2)
	}

	writeResults(results.Results, f.format)

	var serverCount int
	for _, cfg := range results.Configs {
		serverCount += len(cfg.Servers)
	}

	if action == "scan" {
		fmt.Fprintf(os.Stderr, "\nStatic scan: %d servers found. Run 'mcp-audit probe' for SSRF testing.\n", serverCount)
		fmt.Fprintf(os.Stderr, "Or run 'mcp-audit probe --dry-run' to preview without making requests.\n")
	}

	report.PrintSummary(results.Results, serverCount)
	os.Exit(report.ExitCode(results.Results))
}

func runProbe(args []string) {
	f := parseFlags(args)

	s := scanner.NewScanner()
	s.AllowHosts = splitCSV(f.allowHosts)
	s.BlockHosts = splitCSV(f.blockHosts)
	s.Probes = splitCSV(f.targets)
	s.Transport = f.transport
	s.AuthToken = firstNonEmpty(f.authToken, os.Getenv("MCP_AUTH_TOKEN"))
	s.AuthHeaders = splitKeyValue(
		firstNonEmpty(f.authHeaders, os.Getenv("MCP_AUTH_HEADERS")),
	)
	s.TLSCertFile = firstNonEmpty(f.tlsCert, os.Getenv("MCP_TLS_CERT"))
	s.TLSKeyFile = firstNonEmpty(f.tlsKey, os.Getenv("MCP_TLS_KEY"))
	s.ToolAnalysis = !f.noToolAnalysis
	s.SnapshotDir = f.snapshotDir
	s.NoSnapshot = f.noSnapshot
	s.NoTrustOnFirstUse = f.noTrustOnFirstUse
	s.ProbeDepth = scanner.ParseProbeDepth(f.probeDepth)
	s.CallbackPort = f.callbackPort
	s.TargetsFile = f.targetsFile
	if f.maxResponse < 0 {
		fmt.Fprintf(os.Stderr, "probe: --max-response must be >= 0, got %d\n", f.maxResponse)
		os.Exit(2)
	}
	s.MaxResponseSize = min(f.maxResponse, 1048576)
	if err := s.SetTrustConfig(f.trustConfig); err != nil {
		if f.trustConfig != "" {
			fmt.Fprintf(os.Stderr, "probe: trust config error: %v\n", err)
			os.Exit(2)
		}
	}
	dynResults := s.Probe(f.dryRun)

	writeResults(dynResults, f.format)

	var serverCount int
	seen := map[string]bool{}
	for _, r := range dynResults {
		if !seen[r.Server] {
			seen[r.Server] = true
			serverCount++
		}
	}

	report.PrintSummary(dynResults, serverCount)
	os.Exit(report.ExitCode(dynResults))
}

func writeResults(results []scanner.Result, formatFlag string) {
	format := report.ResolveFormat(formatFlag)
	if err := report.Write(os.Stdout, results, format); err != nil {
		fmt.Fprintf(os.Stderr, "error writing output: %v\n", err)
		os.Exit(2)
	}
}

func printUsage() {
	fmt.Println(`mcp-audit — MCP ecosystem security auditor

Usage:
  mcp-audit scan     Full audit (static analysis + dynamic SSRF probing)
  mcp-audit static   Config-only scan (no network requests)
  mcp-audit probe    Dynamic SSRF probe only
  mcp-audit version  Print version
  mcp-audit help     Show this help

Flags:
  --format <fmt>         Output format: table (default), json, sarif
  --dry-run              Print what would be probed without making requests
  --targets <urls>       Comma-separated probe target URLs (overrides built-in list)
  --allow-hosts <ips>    Comma-separated hosts/IPs to allow for probing
  --block-hosts <ips>    Comma-separated hosts/IPs to block from probing
  --probe-depth <level>  Probe depth: basic, extended, full (default: basic)
  --callback-port <n>    Callback listener port for blind SSRF (0=random)
  --targets-file <path>  File with probe target URLs (one per line)
  --max-response <n>     Max response body size in bytes (default 65536, max 1048576)
  --trust-config <path>  Path to trust config JSON (default ~/.config/mcp-audit/trust.json)
  --transport <type>     Force transport type: stdio, sse, http
  --auth-token <token>   Bearer token for MCP server authentication
  --auth-headers <k=v>   Comma-separated key=value auth headers
  --tls-cert <path>      TLS client certificate file for mTLS
  --tls-key <path>       TLS client key file for mTLS
  --no-tool-analysis     Disable tool description and schema security analysis
	  --snapshot-dir <path>  Override snapshot directory (default ~/.config/mcp-audit/snapshots)
	  --no-snapshot           Disable snapshot persistence and drift detection
	  --no-trust-on-first-use Require pre-populated pinned hashes for first scan
	  --no-secret-scan       Disable credential and secret scanning of config files

Examples:
  mcp-audit static
  mcp-audit static --trust-config ./my-trust.json
  mcp-audit scan --format json
  mcp-audit probe --dry-run
  mcp-audit probe --targets http://127.0.0.1:8080/,http://10.0.0.1/
  mcp-audit probe --block-hosts 169.254.169.254
  MCP_AUTH_TOKEN=my-token mcp-audit probe
  mcp-audit probe --probe-depth full
  mcp-audit probe --callback-port 9999
  mcp-audit probe --targets-file ./targets.txt
  mcp-audit probe --transport stdio`)
}
