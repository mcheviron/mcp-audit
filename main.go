package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/mostafaelataby-cheviron/mcp-audit/internal/configfile"
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
	format            report.Format
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
	probeDepth        scanner.ProbeDepth
	callbackPort      int
	targetsFile       string
	maxResponse       int
	verbose           bool
	quiet             bool
	debug             bool
	severityMin       scanner.Severity
	outputFile        string
	timeout           int
	concurrency       int
	noColor           bool
}

var validSeverities = map[string]bool{
	"PASS": true, "INFO": true, "LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true,
}

var validFormats = map[string]bool{"table": true, "json": true, "sarif": true}

var validProbeDepths = map[string]bool{"basic": true, "extended": true, "full": true}

func parseFlags(args []string) (flags, error) {
	var f flags
	var severityMinRaw, probeDepthRaw, formatRaw string

	fs := flag.NewFlagSet("mcp-audit", flag.ContinueOnError)
	fs.StringVar(&formatRaw, "format", "table", "output format: table, json, sarif")
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
	fs.StringVar(&probeDepthRaw, "probe-depth", "basic", "probe depth: basic, extended, full")
	fs.IntVar(&f.callbackPort, "callback-port", 0, "callback listener port (0=random)")
	fs.StringVar(&f.targetsFile, "targets-file", "", "file with probe target URLs (one per line)")
	fs.IntVar(&f.maxResponse, "max-response", 65536, "max response body size in bytes (max 1048576)")
	fs.BoolVar(&f.verbose, "verbose", false, "enable debug logging (DEBUG level)")
	fs.BoolVar(&f.quiet, "quiet", false, "suppress info logs (WARN level and above)")
	fs.BoolVar(&f.debug, "debug", false, "include source file location in log lines")
	fs.StringVar(&severityMinRaw, "severity-min", "",
		"minimum severity to display (PASS, INFO, LOW, MEDIUM, HIGH, CRITICAL)")
	fs.StringVar(&f.outputFile, "output-file", "", "write report to file instead of stdout")
	fs.IntVar(&f.timeout, "timeout", 30, "timeout in seconds for MCP handshake")
	fs.IntVar(&f.concurrency, "concurrency", 10, "maximum concurrent probes")
	fs.BoolVar(&f.noColor, "no-color", false, "disable terminal color codes")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return f, err
	}

	if !validFormats[formatRaw] {
		fmt.Fprintf(os.Stderr, "invalid --format %q: must be table, json, or sarif\n", formatRaw)
		os.Exit(2)
	}
	f.format = report.ResolveFormat(formatRaw)

	if !validProbeDepths[probeDepthRaw] {
		fmt.Fprintf(os.Stderr, "invalid --probe-depth %q: must be basic, extended, or full\n", probeDepthRaw)
		os.Exit(2)
	}
	f.probeDepth = scanner.ParseProbeDepth(probeDepthRaw)

	if severityMinRaw != "" {
		if !validSeverities[severityMinRaw] {
			fmt.Fprintf(os.Stderr,
				"invalid --severity-min %q: must be PASS, INFO, LOW, MEDIUM, HIGH, or CRITICAL\n",
				severityMinRaw)
			os.Exit(2)
		}
		f.severityMin = scanner.ParseSeverity(severityMinRaw)
	}

	return f, nil
}

func newLogger(verbose, quiet, debug bool) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	if quiet {
		level = slog.LevelWarn
	}
	opts := &slog.HandlerOptions{Level: level}
	if debug {
		opts.AddSource = true
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, opts))
	slog.SetDefault(logger)
	return logger
}

type spinner struct {
	stop   chan struct{}
	frames []string
}

func startSpinner(msg string) *spinner {
	s := &spinner{
		stop:   make(chan struct{}),
		frames: []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
	}
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		i := 0
		for {
			select {
			case <-s.stop:
				fmt.Fprintf(os.Stderr, "\r\033[K")
				return
			case <-ticker.C:
				fmt.Fprintf(os.Stderr, "\r%s %s", s.frames[i%len(s.frames)], msg)
				i++
			}
		}
	}()
	return s
}

func (s *spinner) clear() {
	close(s.stop)
}

func applyConfigDefaults(f *flags) {
	cfg := configfile.Load()
	if cfg.Format != "" && f.format == report.FormatTable {
		f.format = report.ResolveFormat(cfg.Format)
	}
	if cfg.TrustConfig != "" && f.trustConfig == "" {
		f.trustConfig = cfg.TrustConfig
	}
	if cfg.Targets != "" && f.targets == "" {
		f.targets = cfg.Targets
	}
	if cfg.AllowHosts != "" && f.allowHosts == "" {
		f.allowHosts = cfg.AllowHosts
	}
	if cfg.BlockHosts != "" && f.blockHosts == "" {
		f.blockHosts = cfg.BlockHosts
	}
	if cfg.Timeout != 0 && f.timeout == 30 {
		f.timeout = cfg.Timeout
	}
	if cfg.Concurrency != 0 && f.concurrency == 10 {
		f.concurrency = cfg.Concurrency
	}
	if cfg.ProbeDepth != "" && f.probeDepth == scanner.DepthBasic {
		f.probeDepth = scanner.ParseProbeDepth(cfg.ProbeDepth)
	}
	if cfg.MaxResponse != 0 && f.maxResponse == 65536 {
		f.maxResponse = cfg.MaxResponse
	}
	if cfg.NoColor && !f.noColor {
		f.noColor = cfg.NoColor
	}
	if cfg.SnapshotDir != "" && f.snapshotDir == "" {
		f.snapshotDir = cfg.SnapshotDir
	}
}

func runStaticAction(action string, args []string) {
	f, err := parseFlags(args)
	if err != nil {
		os.Exit(2)
	}
	applyConfigDefaults(&f)

	logger := newLogger(f.verbose, f.quiet, f.debug)
	logger.Debug("starting", "action", action)

	s := scanner.NewScanner()
	s.NoSecretScan = f.noSecretScan
	if err := s.SetTrustConfig(f.trustConfig); err != nil {
		if f.trustConfig != "" {
			logger.Error("trust config error", "error", err)
			os.Exit(2)
		}
	}

	sp := startSpinner("Discovering configs...")
	results, err := s.Static()
	sp.clear()
	if err != nil {
		logger.Error("scan failed", "error", err)
		os.Exit(2)
	}

	writeResults(results.Results, f)

	var serverCount int
	for _, c := range results.Configs {
		serverCount += len(c.Servers)
	}

	if action == "scan" {
		logger.Info("static scan complete, run probe for SSRF testing", "servers", serverCount)
	}

	report.PrintSummary(results.Results, serverCount)
	os.Exit(report.ExitCode(results.Results))
}

func runProbe(args []string) {
	f, err := parseFlags(args)
	if err != nil {
		os.Exit(2)
	}
	applyConfigDefaults(&f)

	logger := newLogger(f.verbose, f.quiet, f.debug)
	logger.Debug("starting probe")

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
	s.ProbeDepth = f.probeDepth
	s.CallbackPort = f.callbackPort
	s.TargetsFile = f.targetsFile
	s.TimeoutSecs = f.timeout
	s.Concurrency = f.concurrency
	if f.maxResponse < 0 {
		logger.Error("--max-response must be >= 0", "got", f.maxResponse)
		os.Exit(2)
	}
	s.MaxResponseSize = min(f.maxResponse, 1048576)
	if err := s.SetTrustConfig(f.trustConfig); err != nil {
		if f.trustConfig != "" {
			logger.Error("trust config error", "error", err)
			os.Exit(2)
		}
	}

	sp := startSpinner("Probing servers...")
	dynResults := s.Probe(f.dryRun)
	sp.clear()

	writeResults(dynResults, f)

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

func writeResults(results []scanner.Result, f flags) {
	for i := range results {
		scanner.PopulateRemediation(&results[i])
	}
	if f.noColor {
		if err := os.Setenv("NO_COLOR", "1"); err != nil {
			slog.Debug("set NO_COLOR", "err", err)
		}
	}
	if f.severityMin > scanner.SevPass {
		results = filterBySeverity(results, f.severityMin)
	}
	results = report.Deduplicate(results)

	var w io.Writer = os.Stdout
	var outFile *os.File
	if f.outputFile != "" {
		var err error
		outFile, err = os.Create(f.outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error opening output file: %v\n", err)
			os.Exit(2)
		}
		w = outFile
	}

	if err := report.Write(w, results, f.format); err != nil {
		if outFile != nil {
			if cerr := outFile.Close(); cerr != nil {
				slog.Debug("close output file", "err", cerr)
			}
		}
		fmt.Fprintf(os.Stderr, "error writing output: %v\n", err)
		os.Exit(2)
	}
	if outFile != nil {
		if cerr := outFile.Close(); cerr != nil {
			slog.Debug("close output file", "err", cerr)
		}
	}
}

func filterBySeverity(results []scanner.Result, min scanner.Severity) []scanner.Result {
	var filtered []scanner.Result
	for _, r := range results {
		if r.Severity >= min {
			filtered = append(filtered, r)
		}
	}
	return filtered
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
