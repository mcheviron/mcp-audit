package main

import (
	"flag"
	"fmt"
	"os"

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

func parseFlags(args []string) (formatFlag string, output string, dryRun bool) {
	fs := flag.NewFlagSet("mcp-audit", flag.ContinueOnError)
	fs.StringVar(&formatFlag, "format", "table", "output format: table, json, sarif")
	fs.StringVar(&output, "output", "", "write output to file (stdout if empty)")
	fs.BoolVar(&dryRun, "dry-run", false, "print what would be probed without making requests")
	fs.SetOutput(os.Stderr)
	_ = fs.Parse(args)
	return
}

func runStaticAction(action string, args []string) {
	formatFlag, _, _ := parseFlags(args)

	results, err := scanner.RunStatic()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", action, err)
		os.Exit(2)
	}

	writeResults(results.Results, formatFlag)

	var serverCount int
	for _, cfg := range results.Configs {
		serverCount += len(cfg.Servers)
	}

	if action == "scan" {
		fmt.Fprintf(os.Stderr, "\nStatic scan: %d servers found. Run 'mcp-audit probe' for SSRF testing.\n", serverCount)
		fmt.Fprintf(os.Stderr, "Or run 'mcp-audit probe --dry-run' to preview without making requests.\n")
	}

	report.PrintSummary(results.Results, serverCount)
	os.Exit(report.ExitCode(results.Results))
}

func runProbe(args []string) {
	formatFlag, _, dryRun := parseFlags(args)

	dynCfg := scanner.DynamicConfig{DryRun: dryRun}
	dynResults := scanner.RunDynamic(dynCfg)

	writeResults(dynResults, formatFlag)

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

func writeResults(results []scanner.Result, formatFlag string) {
	format := report.ResolveFormat(formatFlag)
	if err := report.Write(os.Stdout, results, format); err != nil {
		fmt.Fprintf(os.Stderr, "error writing output: %v\n", err)
		os.Exit(2)
	}
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
  --format <fmt>     Output format: table (default), json, sarif
  --output <path>    Write output to file (stdout if omitted)
  --dry-run          Print what would be probed without making requests

Examples:
  mcp-audit static
  mcp-audit scan --format json
  mcp-audit probe --dry-run`)
}
