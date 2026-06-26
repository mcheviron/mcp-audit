package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/mcheviron/mcp-audit/internal/config"
	"github.com/mcheviron/mcp-audit/internal/report"
	"github.com/mcheviron/mcp-audit/internal/scanner"
)

var probeCmd = &cobra.Command{
	Use:   "probe",
	Short: "Dynamic SSRF probe only",
	RunE: func(_ *cobra.Command, _ []string) error {
		config.InitRegistry(f.toolsConfig)

		logger := newLogger(f.verbose, f.quiet, f.debug)
		logger.Debug("starting probe")

		if f.llmEndpoint != "" {
			logger.Warn("LLM analysis not yet implemented")
		}

		s, err := setupScanner(f, logger)
		if err != nil {
			return err
		}

		sp := startSpinner("Probing servers...")
		dynResults := s.RunProbe(f.dryRun)
		sp.clear()

		if s.Heuristic.Enabled {
			dynResults = scanner.ComputeServerScores(dynResults, s.LastProbeTools, s.Heuristic.ScoreWeights)
		}

		if s.Adversarial.Enabled {
			logger.Info("running adversarial probes")
			advResults := scanner.RunAdversarialFromScanner(s)
			dynResults = append(dynResults, advResults...)
		}

		scanner.LinkFindings(dynResults)
		dynResults = scanner.MapResultsToCompliance(dynResults)

		probeChains, err := postProcessResults(&dynResults, f, logger)
		if err != nil {
			return err
		}
		if err := writeResults(dynResults, probeChains, f); err != nil {
			return err
		}

		report.PrintSummary(dynResults, report.UniqueServerCount(dynResults))
		if err := exitAfterGateCheck(dynResults, s.Heuristic.MinSecurityScore, s.Heuristic.MaxAbsoluteRisk); err != nil {
			return err
		}
		if code := report.ExitCode(dynResults, false); code != 0 {
			return &exitError{code: code, err: fmt.Errorf("probe completed with findings")}
		}
		return nil
	},
}
