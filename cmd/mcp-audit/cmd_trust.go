package main

import (
	"github.com/spf13/cobra"
)

var trustCmd = &cobra.Command{
	Use:   "trust",
	Short: "Manage trust config (update, export, import)",
}

var trustUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update trust config from remote",
	RunE: func(_ *cobra.Command, _ []string) error {
		return runTrustUpdate()
	},
}

var trustExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export effective trust config",
	RunE: func(_ *cobra.Command, _ []string) error {
		return runTrustExport()
	},
}

var trustImportCmd = &cobra.Command{
	Use:   "import [file]",
	Short: "Import and merge a trust config file",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		return runTrustImport(args[0])
	},
}

func init() {
	trustCmd.AddCommand(trustUpdateCmd, trustExportCmd, trustImportCmd)
}
