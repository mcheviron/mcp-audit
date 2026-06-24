package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/mostafaelataby-cheviron/mcp-audit/internal/completion"
	"github.com/mostafaelataby-cheviron/mcp-audit/internal/config"
	"github.com/mostafaelataby-cheviron/mcp-audit/internal/configfile"
	"github.com/mostafaelataby-cheviron/mcp-audit/internal/report"
	"github.com/mostafaelataby-cheviron/mcp-audit/internal/scanner"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(0)
	}

	cmd := os.Args[1]
	switch cmd {
	case "scan", "static":
		runStaticAction(cmd, os.Args[2:])
	case "probe":
		runProbe(os.Args[2:])
	case "watch":
		runWatch(os.Args[2:])
	case "proxy":
		runProxy(os.Args[2:])
	case "version":
		fmt.Printf("mcp-audit %s\n", version)
		fmt.Printf("  commit: %s\n", commit)
		fmt.Printf("  date:   %s\n", date)
	case "completion":
		shell := "bash"
		if len(os.Args) > 2 {
			shell = os.Args[2]
		}
		if err := completion.Generate(shell, os.Stdout); err != nil {
			os.Exit(1)
		}
	case "trust":
		runTrustCmd(os.Args[2:])
	case "upload":
		runUpload(os.Args[2:])
	case "sbom":
		runSBOM(os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "mcp-audit: unknown command %q\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func splitKeyValue(s string) map[string]string {
	pairs := splitCSV(s)
	if len(pairs) == 0 {
		return nil
	}
	m := make(map[string]string, len(pairs))
	for _, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 {
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

func stripGitRef(ref string) string {
	for _, prefix := range []string{"refs/heads/", "refs/tags/", "refs/pull/"} {
		if after, ok := strings.CutPrefix(ref, prefix); ok {
			return after
		}
	}
	return ref
}

func effectiveFormat(f flags) report.Format {
	if f.ci {
		return report.FormatSARIF
	}
	return f.format
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
	format                report.Format
	dryRun                bool
	allowHosts            string
	blockHosts            string
	targets               string
	trustConfig           string
	transport             string
	authToken             string
	authHeaders           string
	tlsCert               string
	tlsKey                string
	noToolAnalysis        bool
	snapshotDir           string
	noSnapshot            bool
	noTrustOnFirstUse     bool
	noSecretScan          bool
	probeDepth            scanner.ProbeDepth
	callbackPort          int
	targetsFile           string
	maxResponse           int
	verbose               bool
	quiet                 bool
	debug                 bool
	severityMin           scanner.Severity
	outputFile            string
	timeout               int
	concurrency           int
	noColor               bool
	noCrossServerAnalysis bool
	toolsConfig           string
	projectDir            string
	noProject             bool
	noCVEScan             bool
	cveCacheDir           string
	cveCacheTTL           int
	ci                    bool
	ciSummaryFile         string
	ciInfo                report.CIInfo
	heuristic             bool
	scoreWeights          string
	minSecurityScore      float64
	maxAbsoluteRisk       float64
	llmEndpoint           string
	adversarial           bool
	adversarialMaxProbes  int
	blastRadius           bool
	blastRadiusDepth      int
	complianceFramework   string
	exportEvidence        string
	evidenceKey           string
}

var validSeverities = map[string]bool{
	"PASS": true, "INFO": true, "LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true,
}

var validFormats = map[string]bool{"table": true, "json": true, "sarif": true, "junit": true}

var validProbeDepths = map[string]bool{"basic": true, "extended": true, "full": true}

func parseFlags(args []string) (flags, error) { //nolint:funlen
	var f flags
	var severityMinRaw, probeDepthRaw, formatRaw string

	fs := flag.NewFlagSet("mcp-audit", flag.ContinueOnError)
	fs.StringVar(&formatRaw, "format", "table", "output format: table, json, sarif, junit")
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
	fs.BoolVar(&f.noToolAnalysis, "no-tool-analysis", false, "disable tool schema security analysis")
	fs.StringVar(&f.snapshotDir, "snapshot-dir", "", "override snapshot directory (default ~/.config/mcp-audit/snapshots)")
	fs.BoolVar(&f.noSnapshot, "no-snapshot", false, "disable snapshot persistence and drift detection")
	fs.BoolVar(&f.noTrustOnFirstUse, "no-trust-on-first-use", false, "require pinned hashes for first scan")
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
	fs.BoolVar(&f.noCrossServerAnalysis, "no-cross-server-analysis", false, "disable cross-server relationship analysis")
	fs.StringVar(&f.toolsConfig, "tools-config", "", "path to custom tools registry JSON")
	fs.StringVar(&f.projectDir, "project-dir", "", "directory for project-scoped discovery (default: cwd)")
	fs.BoolVar(&f.noProject, "no-project-config", false, "disable project-scoped config discovery")
	fs.BoolVar(&f.noCVEScan, "no-cve-scan", false, "disable CVE vulnerability scanning")
	fs.StringVar(&f.cveCacheDir, "cve-cache-dir", "", "CVE cache directory (default ~/.config/mcp-audit/cve-cache)")
	fs.IntVar(&f.cveCacheTTL, "cve-cache-ttl", 24, "CVE cache TTL in hours")
	fs.BoolVar(&f.ci, "ci", false, "CI mode: force SARIF, print JSON summary, add provenance")
	fs.StringVar(&f.ciSummaryFile, "ci-summary-file", "", "write CI summary JSON to file (CI mode)")
	fs.BoolVar(&f.heuristic, "heuristic", true, "enable heuristic risk scoring")
	fs.StringVar(&f.scoreWeights, "score-weights", "",
		"comma-separated weights: typosquat,cve,capability,description,network")
	fs.Float64Var(&f.minSecurityScore, "min-security-score", 0,
		"fail if any server scores below this threshold (0-100)")
	fs.Float64Var(&f.maxAbsoluteRisk, "max-absolute-risk", 100,
		"fail if any server's absolute risk exceeds this threshold (0-100)")
	fs.StringVar(&f.llmEndpoint, "llm-endpoint", "", "LLM analysis endpoint URL")
	fs.BoolVar(&f.adversarial, "adversarial", false, "enable adversarial prompt injection testing")
	fs.IntVar(&f.adversarialMaxProbes, "adversarial-max-probes", 30, "max adversarial probes per server (0=unlimited)")
	fs.BoolVar(&f.blastRadius, "blast-radius", false, "compute blast-radius dependency chains")
	fs.IntVar(&f.blastRadiusDepth, "blast-radius-depth", 3, "max blast-radius chain depth (1-5)")
	fs.StringVar(&f.complianceFramework, "compliance-framework", "all",
		"compliance framework filter: soc2,nist-ai-rmf,owasp-llm,mitre-atlas,eu-ai-act,all")
	fs.StringVar(&f.exportEvidence, "export-evidence", "", "export signed evidence bundle to path")
	fs.StringVar(&f.evidenceKey, "evidence-key", "", "HMAC key for evidence bundle (hex, default random)")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return f, err
	}
	if f.noProject {
		f.projectDir = ""
	} else if f.projectDir == "" {
		f.projectDir, _ = os.Getwd()
	}
	if !validFormats[formatRaw] {
		fmt.Fprintf(os.Stderr, "invalid --format %q: must be table, json, sarif, or junit\n", formatRaw)
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

	if f.ci {
		f.ciInfo = report.CIInfo{
			Repo:      os.Getenv("GITHUB_REPOSITORY"),
			Branch:    stripGitRef(os.Getenv("GITHUB_REF")),
			CommitSHA: os.Getenv("GITHUB_SHA"),
			Enabled:   true,
		}
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

func defaultCVECacheDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "mcp-audit", "cve-cache")
}

func applyCVECacheDefaults(s *scanner.Scanner, cacheDir string, cacheTTL int) {
	s.CVECacheDir = cacheDir
	s.CVECacheTTLHours = cacheTTL
	if s.CVECacheDir == "" {
		if dir := defaultCVECacheDir(); dir != "" {
			s.CVECacheDir = dir
		}
	}
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
	if cfg.NoCVEScan && !f.noCVEScan {
		f.noCVEScan = cfg.NoCVEScan
	}
	if cfg.CVECacheDir != "" && f.cveCacheDir == "" {
		f.cveCacheDir = cfg.CVECacheDir
	}
	if cfg.CVECacheTTL != 0 && f.cveCacheTTL == 24 {
		f.cveCacheTTL = cfg.CVECacheTTL
	}
}

func runStaticAction(action string, args []string) {
	f, err := parseFlags(args)
	if err != nil {
		os.Exit(2)
	}
	applyConfigDefaults(&f)

	config.InitRegistry(f.toolsConfig)

	logger := newLogger(f.verbose, f.quiet, f.debug)
	logger.Debug("starting", "action", action)

	s := setupScanner(f, logger)
	s.NoSecretScan = f.noSecretScan

	sp := startSpinner("Discovering configs...")
	results, err := s.Static()
	sp.clear()
	if err != nil {
		logger.Error("scan failed", "error", err)
		os.Exit(4)
	}

	if s.HeuristicEnabled {
		results.Results = scanner.ComputeServerScores(results.Results, nil, s.ScoreWeights)
	}

	scanner.LinkFindings(results.Results)
	results.Results = scanner.MapResultsToCompliance(results.Results)

	chains := postProcessResults(&results.Results, f, logger)

	writeResults(results.Results, chains, f)

	var serverCount int
	for _, c := range results.Configs {
		serverCount += len(c.Servers)
	}

	if action == "scan" {
		logger.Info("static scan complete, run probe for SSRF testing", "servers", serverCount)
	}

	report.PrintSummary(results.Results, serverCount)
	exitAfterGateCheck(results.Results, s.MinSecurityScore, s.MaxAbsoluteRisk)
	os.Exit(report.ExitCode(results.Results))
}

func runProbe(args []string) {
	f, err := parseFlags(args)
	if err != nil {
		os.Exit(2)
	}
	applyConfigDefaults(&f)

	config.InitRegistry(f.toolsConfig)

	logger := newLogger(f.verbose, f.quiet, f.debug)
	logger.Debug("starting probe")

	if f.llmEndpoint != "" {
		logger.Warn("LLM analysis not yet implemented")
	}

	s := setupScanner(f, logger)

	sp := startSpinner("Probing servers...")
	dynResults := s.Probe(f.dryRun)
	sp.clear()

	if s.HeuristicEnabled {
		dynResults = scanner.ComputeServerScores(dynResults, s.LastProbeTools, s.ScoreWeights)
	}

	if s.Adversarial {
		logger.Info("running adversarial probes")
		advResults := scanner.RunAdversarialFromScanner(s)
		dynResults = append(dynResults, advResults...)
	}

	scanner.LinkFindings(dynResults)
	dynResults = scanner.MapResultsToCompliance(dynResults)

	probeChains := postProcessResults(&dynResults, f, logger)
	writeResults(dynResults, probeChains, f)

	report.PrintSummary(dynResults, report.UniqueServerCount(dynResults))
	exitAfterGateCheck(dynResults, s.MinSecurityScore, s.MaxAbsoluteRisk)
	os.Exit(report.ExitCode(dynResults))
}

func postProcessResults(results *[]scanner.Result, f flags, logger *slog.Logger) []scanner.Chain {
	var chains []scanner.Chain
	if f.blastRadius {
		chains = scanner.ComputeChains(*results, f.blastRadiusDepth)
	}

	if f.exportEvidence != "" {
		evidenceKey := f.evidenceKey
		if evidenceKey == "" {
			buf := make([]byte, 32)
			if _, err := rand.Read(buf); err != nil {
				logger.Error("failed to generate evidence key", "error", err)
				os.Exit(4)
			}
			evidenceKey = hex.EncodeToString(buf)
			fmt.Fprintf(os.Stderr, "Evidence HMAC key: %s\n", evidenceKey)
		}
		if err := report.ExportEvidence(f.exportEvidence, evidenceKey, *results, chains); err != nil {
			logger.Error("evidence export failed", "error", err)
			os.Exit(4)
		}
	}

	if f.complianceFramework != "all" && f.complianceFramework != "" {
		*results = scanner.FilterByFramework(*results, f.complianceFramework)
	}

	return chains
}

func setupScanner(f flags, logger *slog.Logger) *scanner.Scanner {
	s := scanner.NewScanner()
	s.ProjectDir = f.projectDir
	s.NoCVEScan = f.noCVEScan
	applyScoreConfig(s, f, logger)
	applyCVECacheDefaults(s, f.cveCacheDir, f.cveCacheTTL)
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
	s.CrossServerAnalysis = !f.noCrossServerAnalysis
	s.Adversarial = f.adversarial
	s.AdversarialMaxProbes = f.adversarialMaxProbes
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
		os.Exit(4)
	}
	s.MaxResponseSize = min(f.maxResponse, 1048576)
	if err := s.SetTrustConfig(f.trustConfig); err != nil {
		if f.trustConfig != "" {
			logger.Error("trust config error", "error", err)
			os.Exit(4)
		}
	}
	return s
}

func writeResults(results []scanner.Result, chains []scanner.Chain, f flags) {
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

	var ciPtr *report.CIInfo
	if f.ci {
		ciPtr = &f.ciInfo
	}

	if err := report.Write(w, results, chains, effectiveFormat(f), ciPtr); err != nil {
		if outFile != nil {
			cerr := outFile.Close()
			if cerr != nil {
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

	if f.ci {
		ciWriter := os.Stdout
		if f.ciSummaryFile != "" {
			sf, err := os.Create(f.ciSummaryFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error opening CI summary file: %v\n", err)
			} else {
				ciWriter = sf
				defer func() {
					if cerr := sf.Close(); cerr != nil {
						slog.Debug("close CI summary file", "err", cerr)
					}
				}()
			}
		}
		if err := report.WriteCISummary(ciWriter, results, report.UniqueServerCount(results)); err != nil {
			fmt.Fprintf(os.Stderr, "error writing CI summary: %v\n", err)
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

func applyScoreConfig(s *scanner.Scanner, f flags, logger *slog.Logger) {
	s.HeuristicEnabled = f.heuristic
	if w, err := scanner.ParseWeights(f.scoreWeights); err != nil {
		logger.Error("invalid score weights", "error", err)
		os.Exit(4)
	} else {
		s.ScoreWeights = w
	}
	s.MinSecurityScore = f.minSecurityScore
	s.MaxAbsoluteRisk = f.maxAbsoluteRisk
}

func exitAfterGateCheck(results []scanner.Result, minScore, maxRisk float64) {
	for _, r := range results {
		if r.Score > 0 && r.Score < minScore {
			fmt.Fprintf(os.Stderr, "Failing: server %q scored %.0f below minimum %.0f\n",
				r.Server, r.Score, minScore)
			os.Exit(2)
		}
		risk := 100 - r.Score
		if r.Score > 0 && risk > maxRisk {
			fmt.Fprintf(os.Stderr, "Failing: server %q absolute risk %.0f above maximum %.0f\n",
				r.Server, risk, maxRisk)
			os.Exit(2)
		}
	}
}

func printUsage() {
	fmt.Println(`mcp-audit — MCP ecosystem security auditor
Usage:
  mcp-audit scan        Full audit (static + SSRF probing)
  mcp-audit static      Config-only scan
  mcp-audit probe       Dynamic SSRF probe only
  mcp-audit watch       Watch config files and re-scan on changes
  mcp-audit proxy       Start a transparent MCP proxy
  mcp-audit trust       Manage trust config (update, export, import)
  mcp-audit upload      Upload anonymized findings to community DB
  mcp-audit sbom        Generate Software Bill of Materials
  mcp-audit version     Print version
  mcp-audit completion  Generate shell completion
  mcp-audit help        Show this help

Scan/probe flags:
  --format <fmt>         Output: table (default), json, sarif, junit
  --dry-run              Print what would be probed without requests
  --targets <urls>       Comma-separated override probe target URLs
  --allow-hosts <ips>    Comma-separated hosts/IPs to allow
  --block-hosts <ips>    Comma-separated hosts/IPs to block
  --probe-depth <level>  Probe depth: basic, extended, full (basic)
  --callback-port <n>    Callback port for blind SSRF (0=random)
  --targets-file <path>  File with probe target URLs (one per line)
  --max-response <n>     Max response bytes (default 65536)
  --trust-config <path>  Path to trust config JSON
  --transport <type>     Force transport: stdio, sse, http
  --auth-token <token>   Bearer token for MCP authentication
  --auth-headers <k=v>   Comma-separated key=value auth headers
  --tls-cert <path>      TLS client cert file for mTLS
  --tls-key <path>       TLS client key file for mTLS
  --no-tool-analysis     Disable tool schema analysis
  --no-snapshot          Disable snapshot persistence and drift detection
  --no-trust-on-first-use Require pinned hashes for first scan
  --no-secret-scan       Disable credential and secret scanning
  --no-cross-server-analysis Disable cross-server relationship analysis
  --no-cve-scan          Disable CVE vulnerability scanning
  --cve-cache-dir <path> CVE cache directory (default ~/.config/mcp-audit/cve-cache)
  --cve-cache-ttl <n>    CVE cache TTL in hours (default: 24)
  --tools-config <path>  Path to custom tools registry JSON
  --ci                   CI mode: force SARIF, print JSON summary, add provenance
Watch/Proxy flags:
  --watch-interval <n>   Re-scan interval in seconds (default: 300)
  --listen <addr>        Listen addr (default: 127.0.0.1:8080)
  --block-critical       Block responses with CRITICAL findings
SBOM flags:
  --format <fmt>         Output: cyclonedx-json (default), cyclonedx-xml, spdx-json, spdx-tag
  --with-cves            Include CVE vulnerability data in SBOM
  --output <path>        Write SBOM to file instead of stdout
  --config-root <dir>    Override project directory for config discovery`)
}
