package main

import (
	"fmt"
	"os"

	"github.com/hashicorp/go-set"
	"github.com/spf13/cobra"

	"github.com/mostafaelataby-cheviron/mcp-audit/internal/config"
	"github.com/mostafaelataby-cheviron/mcp-audit/internal/sbom"
	"github.com/mostafaelataby-cheviron/mcp-audit/internal/scanner"
)

var sbomCmd = &cobra.Command{
	Use:   "sbom",
	Short: "Generate Software Bill of Materials",
	RunE: func(cmd *cobra.Command, _ []string) error {
		format, _ := cmd.Flags().GetString("format")
		withCVEs, _ := cmd.Flags().GetBool("with-cves")
		output, _ := cmd.Flags().GetString("output")
		configRoot, _ := cmd.Flags().GetString("config-root")

		cwd := configRoot
		if cwd == "" {
			var err error
			cwd, err = os.Getwd()
			if err != nil {
				return &exitError{code: 1, err: fmt.Errorf("get working directory: %w", err)}
			}
		}

		config.InitRegistry("")
		cfgs := config.Discover(cwd)
		servers := sbom.NewDiscoveredServers(cfgs)

		var cves map[string][]sbom.CVEResult
		if withCVEs {
			cves = collectCVEsFromScan(cfgs)
		}

		var data []byte
		var err error

		switch format {
		case "cyclonedx-json":
			bom := sbom.NewCycloneDX(servers, cves, version)
			data, err = bom.ToJSON()
		case "cyclonedx-xml":
			bom := sbom.NewCycloneDX(servers, cves, version)
			data, err = bom.ToXML()
		case "spdx-json":
			doc := sbom.NewSPDX(servers, cves, version)
			data, err = doc.ToJSON()
		case "spdx-tag":
			doc := sbom.NewSPDX(servers, cves, version)
			data, err = doc.ToTagValue()
		default:
			return &exitError{code: 1, err: fmt.Errorf(
				"mcp-audit sbom: unknown format %q (valid: cyclonedx-json, cyclonedx-xml, spdx-json, spdx-tag)", format)}
		}

		if err != nil {
			return &exitError{code: 1, err: fmt.Errorf("mcp-audit sbom: %w", err)}
		}

		if output != "" {
			if err := os.WriteFile(output, data, 0600); err != nil {
				return &exitError{code: 1, err: fmt.Errorf("mcp-audit sbom: write %s: %w", output, err)}
			}
			fmt.Fprintf(os.Stderr, "SBOM written to %s\n", output)
		} else {
			_, _ = os.Stdout.Write(data)
			_, _ = os.Stdout.WriteString("\n")
		}
		return nil
	},
}

func init() {
	sbomCmd.Flags().String("format", "cyclonedx-json", "output format: cyclonedx-json, cyclonedx-xml, spdx-json, spdx-tag")
	sbomCmd.Flags().Bool("with-cves", false, "include CVE vulnerability data in SBOM")
	sbomCmd.Flags().String("output", "", "write SBOM to file instead of stdout")
	sbomCmd.Flags().String("config-root", "", "override project directory for config discovery")
}

func collectCVEsFromScan(cfgs []config.Config) map[string][]sbom.CVEResult {
	s := scanner.New()
	s.NoCVEScan = false
	res, err := s.Static()
	if err != nil {
		return nil
	}

	packages := set.New[string](0)
	for _, cfg := range cfgs {
		for _, srv := range cfg.Servers {
			if srv.Package != "" {
				packages.Insert(srv.Package)
			}
		}
	}

	cves := make(map[string][]sbom.CVEResult)
	for _, r := range res.Results {
		if r.Type != "cve" {
			continue
		}
		if !packages.Contains(r.Server) {
			continue
		}
		cves[r.Server] = append(cves[r.Server], sbom.CVEResult{
			ID:          r.Finding,
			Description: r.Detail,
		})
	}
	return cves
}
