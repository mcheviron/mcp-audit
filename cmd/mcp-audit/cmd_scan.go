package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/mcheviron/mcp-audit/internal/config"
	"github.com/mcheviron/mcp-audit/internal/report"
	"github.com/mcheviron/mcp-audit/internal/scanner"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Full audit (static + SSRF probing)",
	RunE:  runScanE,
}

var staticCmd = &cobra.Command{
	Use:   "static",
	Short: "Config-only scan",
	RunE:  runScanE,
}

func runScanE(cmd *cobra.Command, _ []string) error {
	config.InitRegistry(f.toolsConfig)
	logger := newLogger(f.verbose, f.quiet, f.debug)
	logger.Debug("starting", "action", cmd.Name())

	s, err := setupScanner(f, logger)
	if err != nil {
		return err
	}
	s.NoSecretScan = f.noSecretScan

	sp := startSpinner("Discovering configs...")
	results, err := s.Static()
	sp.clear()
	if err != nil {
		logger.Error("scan failed", "error", err)
		return &exitError{code: 4, err: fmt.Errorf("scan failed: %w", err)}
	}

	if s.HeuristicEnabled {
		results.Results = scanner.ComputeServerScores(results.Results, nil, s.ScoreWeights)
	}

	scanner.LinkFindings(results.Results)
	results.Results = scanner.MapResultsToCompliance(results.Results)

	chains, err := postProcessResults(&results.Results, f, logger)
	if err != nil {
		return err
	}
	if err := writeResults(results.Results, chains, f); err != nil {
		return err
	}

	var serverCount int
	for _, c := range results.Configs {
		serverCount += len(c.Servers)
	}

	if cmd.Name() == "scan" {
		logger.Info("static scan complete, run probe for SSRF testing", "servers", serverCount)
	}

	report.PrintSummary(results.Results, serverCount)
	if err := exitAfterGateCheck(results.Results, s.MinSecurityScore, s.MaxAbsoluteRisk); err != nil {
		return err
	}
	if code := report.ExitCode(results.Results); code != 0 {
		return &exitError{code: code, err: fmt.Errorf("scan completed with findings")}
	}
	return nil
}

func setupScanner(f flags, logger *slog.Logger) (*scanner.Scanner, error) {
	s := scanner.New()
	s.ProjectDir = f.projectDir
	s.NoCVEScan = f.noCVEScan
	if err := applyScoreConfig(s, f, logger); err != nil {
		return nil, err
	}
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
		return nil, &exitError{code: 4, err: fmt.Errorf("--max-response must be >= 0, got %d", f.maxResponse)}
	}
	s.MaxResponseSize = min(f.maxResponse, 1048576)
	if err := s.SetTrustConfig(f.trustConfig); err != nil {
		if f.trustConfig != "" {
			logger.Error("trust config error", "error", err)
			return nil, &exitError{code: 4, err: fmt.Errorf("trust config error: %w", err)}
		}
	}
	return s, nil
}

func applyScoreConfig(s *scanner.Scanner, f flags, logger *slog.Logger) error {
	s.HeuristicEnabled = f.heuristic
	if w, err := scanner.ParseWeights(f.scoreWeights); err != nil {
		logger.Error("invalid score weights", "error", err)
		return &exitError{code: 4, err: fmt.Errorf("invalid score weights: %w", err)}
	} else {
		s.ScoreWeights = w
	}
	s.MinSecurityScore = f.minSecurityScore
	s.MaxAbsoluteRisk = f.maxAbsoluteRisk
	return nil
}

func exitAfterGateCheck(results []scanner.Result, minScore, maxRisk float64) error {
	for _, r := range results {
		if r.Score > 0 && r.Score < minScore {
			return &exitError{code: 2, err: fmt.Errorf("failing: server %q scored %.0f below minimum %.0f",
				r.Server, r.Score, minScore)}
		}
		risk := 100 - r.Score
		if r.Score > 0 && risk > maxRisk {
			return &exitError{code: 2, err: fmt.Errorf("failing: server %q absolute risk %.0f above maximum %.0f",
				r.Server, risk, maxRisk)}
		}
	}
	return nil
}
