package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/mcheviron/mcp-audit/internal/configfile"
	"github.com/mcheviron/mcp-audit/internal/report"
	"github.com/mcheviron/mcp-audit/internal/scanner"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

var f flags

var rootCmd = &cobra.Command{
	Use:               "mcp-audit",
	Short:             "MCP ecosystem security auditor",
	SilenceErrors:     true,
	SilenceUsage:      true,
	PersistentPreRunE: runPersistentPre,
}

func init() {
	setupRootFlags(rootCmd.PersistentFlags())
	rootCmd.AddCommand(scanCmd, staticCmd, probeCmd, watchCmd, proxyCmd)
	rootCmd.AddCommand(trustCmd, uploadCmd, sbomCmd)
	rootCmd.SetVersionTemplate("mcp-audit {{.Version}}\n  commit: " + commit + "\n  date:   " + date + "\n")
	rootCmd.Version = version
}

func runPersistentPre(_ *cobra.Command, _ []string) error {
	return validateAndApply(&f)
}

func setupRootFlags(pf *pflag.FlagSet) {
	pf.StringVar(&f.formatRaw, "format", "table", "output format: table, json, sarif, junit")
	pf.BoolVar(&f.dryRun, "dry-run", false, "print what would be probed without making requests")
	pf.StringVar(&f.allowHosts, "allow-hosts", "", "comma-separated hosts/IPs to allow for probing")
	pf.StringVar(&f.blockHosts, "block-hosts", "", "comma-separated hosts/IPs to block from probing")
	pf.StringVar(&f.targets, "targets", "", "comma-separated probe target URLs (overrides defaults)")
	pf.StringVar(&f.trustConfig, "trust-config", "", "path to trust config JSON")
	pf.StringVar(&f.transport, "transport", "", "force transport type: stdio, sse, http")
	pf.StringVar(&f.authToken, "auth-token", "", "Bearer token for MCP server authentication")
	pf.StringVar(&f.authHeaders, "auth-headers", "", "comma-separated key=value auth headers")
	pf.StringVar(&f.tlsCert, "tls-cert", "", "TLS client certificate file for mTLS")
	pf.StringVar(&f.tlsKey, "tls-key", "", "TLS client key file for mTLS")
	pf.BoolVar(&f.noToolAnalysis, "no-tool-analysis", false, "disable tool schema security analysis")
	pf.StringVar(&f.snapshotDir, "snapshot-dir", "", "override snapshot directory")
	pf.BoolVar(&f.noSnapshot, "no-snapshot", false, "disable snapshot persistence and drift detection")
	pf.BoolVar(&f.noTrustOnFirstUse, "no-trust-on-first-use", false, "require pinned hashes for first scan")
	pf.BoolVar(&f.noSecretScan, "no-secret-scan", false, "disable credential and secret scanning")
	pf.StringVar(&f.probeDepthRaw, "probe-depth", "basic", "probe depth: basic, extended, full")
	pf.IntVar(&f.callbackPort, "callback-port", 0, "callback listener port (0=random)")
	pf.StringVar(&f.targetsFile, "targets-file", "", "file with probe target URLs (one per line)")
	pf.IntVar(&f.maxResponse, "max-response", 65536, "max response body size in bytes (max 1048576)")
	pf.BoolVar(&f.verbose, "verbose", false, "enable debug logging (DEBUG level)")
	pf.BoolVar(&f.quiet, "quiet", false, "suppress info logs (WARN level and above)")
	pf.BoolVar(&f.debug, "debug", false, "include source file location in log lines")
	pf.StringVar(&f.severityMinRaw, "severity-min", "", "minimum severity to display")
	pf.StringVar(&f.outputFile, "output-file", "", "write report to file instead of stdout")
	pf.IntVar(&f.timeout, "timeout", 30, "timeout in seconds for MCP handshake")
	pf.IntVar(&f.concurrency, "concurrency", 10, "maximum concurrent probes")
	pf.BoolVar(&f.noColor, "no-color", false, "disable terminal color codes")
	pf.BoolVar(&f.noCrossServerAnalysis, "no-cross-server-analysis", false, "disable cross-server analysis")
	pf.StringVar(&f.toolsConfig, "tools-config", "", "path to custom tools registry JSON")
	pf.StringVar(&f.projectDir, "project-dir", "", "directory for project-scoped discovery")
	pf.BoolVar(&f.noProject, "no-project-config", false, "disable project-scoped config discovery")
	pf.BoolVar(&f.noCVEScan, "no-cve-scan", false, "disable CVE vulnerability scanning")
	pf.StringVar(&f.cveCacheDir, "cve-cache-dir", "", "CVE cache directory")
	pf.IntVar(&f.cveCacheTTL, "cve-cache-ttl", 24, "CVE cache TTL in hours")
	pf.BoolVar(&f.ci, "ci", false, "CI mode: force SARIF, print JSON summary, add provenance")
	pf.StringVar(&f.ciSummaryFile, "ci-summary-file", "", "write CI summary JSON to file")
	pf.BoolVar(&f.heuristic, "heuristic", true, "enable heuristic risk scoring")
	pf.StringVar(&f.scoreWeights, "score-weights", "", "comma-separated weights for scoring")
	pf.Float64Var(&f.minSecurityScore, "min-security-score", 0, "fail if server scores below threshold")
	pf.Float64Var(&f.maxAbsoluteRisk, "max-absolute-risk", 100, "fail if absolute risk exceeds threshold")
	pf.StringVar(&f.llmEndpoint, "llm-endpoint", "", "LLM analysis endpoint URL")
	pf.BoolVar(&f.adversarial, "adversarial", false, "enable adversarial prompt injection testing")
	pf.IntVar(&f.adversarialMaxProbes, "adversarial-max-probes", 30, "max adversarial probes per server")
	pf.BoolVar(&f.blastRadius, "blast-radius", false, "compute blast-radius dependency chains")
	pf.IntVar(&f.blastRadiusDepth, "blast-radius-depth", 3, "max blast-radius chain depth (1-5)")
	pf.StringVar(&f.complianceFramework, "compliance-framework", "all", "compliance framework filter")
	pf.StringVar(&f.exportEvidence, "export-evidence", "", "export signed evidence bundle to path")
	pf.StringVar(&f.evidenceKey, "evidence-key", "", "HMAC key for evidence bundle (hex)")
}

func parseFlags(args []string) (flags, error) { //nolint:unused // called by tests
	tmp := &cobra.Command{DisableFlagParsing: false}
	setupRootFlags(tmp.PersistentFlags())
	tmp.PersistentPreRunE = func(_ *cobra.Command, _ []string) error {
		return nil
	}
	tmp.SetArgs(args)
	if err := tmp.Execute(); err != nil {
		return flags{}, err
	}
	result := extractFlagValues(tmp.PersistentFlags())
	if err := validateAndApply(&result); err != nil {
		return result, err
	}
	return result, nil
}

func extractFlagValues(pf *pflag.FlagSet) flags { //nolint:unused // called by parseFlags which is used by tests
	var r flags
	r.formatRaw, _ = pf.GetString("format")
	r.dryRun, _ = pf.GetBool("dry-run")
	r.allowHosts, _ = pf.GetString("allow-hosts")
	r.blockHosts, _ = pf.GetString("block-hosts")
	r.targets, _ = pf.GetString("targets")
	r.trustConfig, _ = pf.GetString("trust-config")
	r.transport, _ = pf.GetString("transport")
	r.authToken, _ = pf.GetString("auth-token")
	r.authHeaders, _ = pf.GetString("auth-headers")
	r.tlsCert, _ = pf.GetString("tls-cert")
	r.tlsKey, _ = pf.GetString("tls-key")
	r.noToolAnalysis, _ = pf.GetBool("no-tool-analysis")
	r.snapshotDir, _ = pf.GetString("snapshot-dir")
	r.noSnapshot, _ = pf.GetBool("no-snapshot")
	r.noTrustOnFirstUse, _ = pf.GetBool("no-trust-on-first-use")
	r.noSecretScan, _ = pf.GetBool("no-secret-scan")
	r.probeDepthRaw, _ = pf.GetString("probe-depth")
	r.callbackPort, _ = pf.GetInt("callback-port")
	r.targetsFile, _ = pf.GetString("targets-file")
	r.maxResponse, _ = pf.GetInt("max-response")
	r.verbose, _ = pf.GetBool("verbose")
	r.quiet, _ = pf.GetBool("quiet")
	r.debug, _ = pf.GetBool("debug")
	r.severityMinRaw, _ = pf.GetString("severity-min")
	r.outputFile, _ = pf.GetString("output-file")
	r.timeout, _ = pf.GetInt("timeout")
	r.concurrency, _ = pf.GetInt("concurrency")
	r.noColor, _ = pf.GetBool("no-color")
	r.noCrossServerAnalysis, _ = pf.GetBool("no-cross-server-analysis")
	r.toolsConfig, _ = pf.GetString("tools-config")
	r.projectDir, _ = pf.GetString("project-dir")
	r.noProject, _ = pf.GetBool("no-project-config")
	r.noCVEScan, _ = pf.GetBool("no-cve-scan")
	r.cveCacheDir, _ = pf.GetString("cve-cache-dir")
	r.cveCacheTTL, _ = pf.GetInt("cve-cache-ttl")
	r.ci, _ = pf.GetBool("ci")
	r.ciSummaryFile, _ = pf.GetString("ci-summary-file")
	r.heuristic, _ = pf.GetBool("heuristic")
	r.scoreWeights, _ = pf.GetString("score-weights")
	r.minSecurityScore, _ = pf.GetFloat64("min-security-score")
	r.maxAbsoluteRisk, _ = pf.GetFloat64("max-absolute-risk")
	r.llmEndpoint, _ = pf.GetString("llm-endpoint")
	r.adversarial, _ = pf.GetBool("adversarial")
	r.adversarialMaxProbes, _ = pf.GetInt("adversarial-max-probes")
	r.blastRadius, _ = pf.GetBool("blast-radius")
	r.blastRadiusDepth, _ = pf.GetInt("blast-radius-depth")
	r.complianceFramework, _ = pf.GetString("compliance-framework")
	r.exportEvidence, _ = pf.GetString("export-evidence")
	r.evidenceKey, _ = pf.GetString("evidence-key")
	return r
}

func validateAndApply(f *flags) error {
	if f.noProject {
		f.projectDir = ""
	} else if f.projectDir == "" {
		f.projectDir, _ = os.Getwd()
	}
	if !validFormats.Contains(f.formatRaw) {
		return fmt.Errorf("invalid --format %q: must be table, json, sarif, or junit", f.formatRaw)
	}
	f.format = report.ResolveFormat(f.formatRaw)
	if !validProbeDepths.Contains(f.probeDepthRaw) {
		return fmt.Errorf("invalid --probe-depth %q: must be basic, extended, or full", f.probeDepthRaw)
	}
	f.probeDepth = scanner.ParseProbeDepth(f.probeDepthRaw)
	if f.severityMinRaw != "" {
		if !validSeverities.Contains(f.severityMinRaw) {
			return fmt.Errorf(
				"invalid --severity-min %q: must be PASS, INFO, LOW, MEDIUM, HIGH, or CRITICAL",
				f.severityMinRaw,
			)
		}
		f.severityMin = scanner.ParseSeverity(f.severityMinRaw)
	}
	if f.ci {
		f.ciInfo = report.CIInfo{
			Repo:      os.Getenv("GITHUB_REPOSITORY"),
			Branch:    stripGitRef(os.Getenv("GITHUB_REF")),
			CommitSHA: os.Getenv("GITHUB_SHA"),
			Enabled:   true,
		}
	}
	applyConfigDefaults(f)
	return nil
}

type flags struct {
	formatRaw             string
	probeDepthRaw         string
	severityMinRaw        string
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
