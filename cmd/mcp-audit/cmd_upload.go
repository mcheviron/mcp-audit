package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/mostafaelataby-cheviron/mcp-audit/internal/scanner"
)

var uploadCmd = &cobra.Command{
	Use:   "upload",
	Short: "Upload anonymized findings to community DB",
	RunE: func(_ *cobra.Command, _ []string) error {
		logger := newLogger(f.verbose, f.quiet, f.debug)
		logger.Debug("starting upload")

		s := scanner.NewScanner()
		if !f.noProject {
			s.ProjectDir = f.projectDir
		}
		s.NoSecretScan = f.noSecretScan
		if err := s.SetTrustConfig(f.trustConfig); err != nil {
			if f.trustConfig != "" {
				logger.Error("trust config error", "error", err)
				return &exitError{code: 4, err: fmt.Errorf("trust config error: %w", err)}
			}
		}

		results, err := s.Static()
		if err != nil {
			logger.Error("scan failed", "error", err)
			return &exitError{code: 4, err: fmt.Errorf("scan failed: %w", err)}
		}

		payload := anonymizeFindings(results.Results)
		if len(payload.Findings) == 0 {
			fmt.Println("No findings to upload.")
			return nil
		}

		displayPayload(payload)

		fmt.Print("\nUpload these anonymized findings to community DB? [y/N]: ")
		if !readYes() {
			fmt.Println("Upload cancelled.")
			return nil
		}

		if err := postPayload(communityUploadURL, payload); err != nil {
			fmt.Fprintf(os.Stderr, "upload: POST failed: %v\n", err)
			fmt.Println("Findings could not be uploaded. You can submit them manually at:")
			fmt.Println("  https://github.com/mcp-audit-db/issues/new")
			return &exitError{code: 4, err: fmt.Errorf("upload: POST failed: %w", err)}
		}

		fmt.Println("Upload complete. Thank you for contributing to the community DB.")
		return nil
	},
}
