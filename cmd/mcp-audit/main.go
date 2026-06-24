package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/hashicorp/go-set"

	"github.com/mcheviron/mcp-audit/internal/report"
	"github.com/mcheviron/mcp-audit/internal/scanner"
)

type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

var validSeverities = set.From[string]([]string{
	"PASS", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL",
})

var validFormats = set.From[string]([]string{"table", "json", "sarif", "junit"})

var validProbeDepths = set.From[string]([]string{"basic", "extended", "full"})

func main() {
	if err := rootCmd.Execute(); err != nil {
		if ee, ok := errors.AsType[*exitError](err); ok {
			os.Exit(ee.code)
		}
		os.Exit(1)
	}
}

func postProcessResults(results *[]scanner.Result, f flags, logger *slog.Logger) ([]scanner.Chain, error) {
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
				return nil, &exitError{code: 4, err: fmt.Errorf("failed to generate evidence key: %w", err)}
			}
			evidenceKey = hex.EncodeToString(buf)
			keyPath := f.exportEvidence + ".key"
			if err := os.WriteFile(keyPath, []byte(evidenceKey+"\n"), 0600); err != nil {
				logger.Error("failed to write evidence key file", "error", err, "path", keyPath)
				return nil, &exitError{code: 4, err: fmt.Errorf("failed to write evidence key file: %w", err)}
			}
			fmt.Fprintf(os.Stderr, "Evidence HMAC key written to: %s\n", keyPath)
		}
		if err := report.ExportEvidence(f.exportEvidence, evidenceKey, *results, chains); err != nil {
			logger.Error("evidence export failed", "error", err)
			return nil, &exitError{code: 4, err: fmt.Errorf("evidence export failed: %w", err)}
		}
	}

	if f.complianceFramework != "all" && f.complianceFramework != "" {
		*results = scanner.FilterByFramework(*results, f.complianceFramework)
	}

	return chains, nil
}

func writeResults(results []scanner.Result, chains []scanner.Chain, f flags) error {
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
			return &exitError{code: 2, err: fmt.Errorf("error opening output file: %w", err)}
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
		return &exitError{code: 2, err: fmt.Errorf("error writing output: %w", err)}
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
	return nil
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
