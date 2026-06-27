package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/mcheviron/mcp-audit/internal/manifest"
)

var (
	verifyText bool
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Print a deterministic manifest of the binary's identity and embedded data",
	Long: "Print a JSON manifest describing the binary version, git commit, build date, " +
		"Go runtime version, embedded data SHA-256 hashes, and output format schema versions. " +
		"Same binary produces byte-identical output, suitable for piping into sha256sum or jq.",
	RunE: runVerify,
}

func init() {
	verifyCmd.Flags().BoolVar(&verifyText, "text", false, "print human-readable text instead of JSON")
}

func runVerify(_ *cobra.Command, _ []string) error {
	m := manifest.Build()
	if verifyText {
		return m.WriteText(os.Stdout)
	}
	return m.WriteJSON(os.Stdout)
}
