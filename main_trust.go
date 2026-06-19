package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mostafaelataby-cheviron/mcp-audit/internal/config"
	"github.com/mostafaelataby-cheviron/mcp-audit/internal/intel"
)

var trustUpdateURL = "https://github.com/mcp-audit-db/releases/latest/download/trust.json"

func runTrustCmd(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "trust: missing subcommand (update, export, import)")
		os.Exit(2)
	}

	switch args[0] {
	case "update":
		runTrustUpdate()
	case "export":
		runTrustExport()
	case "import":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "trust import: missing file argument")
			os.Exit(2)
		}
		runTrustImport(args[1])
	default:
		fmt.Fprintf(os.Stderr, "trust: unknown subcommand %q, expected update, export, or import\n", args[0])
		os.Exit(2)
	}
}

func trustConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home directory: %w", err)
	}
	dir := filepath.Join(home, ".config", "mcp-audit")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("create config directory: %w", err)
	}
	return dir, nil
}

func runTrustUpdate() {
	dir, err := trustConfigDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "trust update: %v\n", err)
		os.Exit(4)
	}

	remoteData, err := fetchURL(trustUpdateURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "trust update: failed to fetch latest trust config: %v\n", err)
		os.Exit(4)
	}

	var remoteFile intel.TrustFile
	if err := json.Unmarshal(remoteData, &remoteFile); err != nil {
		fmt.Fprintf(os.Stderr, "trust update: invalid remote trust config: %v\n", err)
		os.Exit(4)
	}

	localPath := filepath.Join(dir, "trust.json")
	if data, err := os.ReadFile(localPath); err == nil { //nolint:gosec
		var localFile intel.TrustFile
		if json.Unmarshal(data, &localFile) == nil {
			if localFile.Version != remoteFile.Version || localFile.GeneratedAt != remoteFile.GeneratedAt {
				promptOverwrite(localPath, &localFile, &remoteFile)
				return
			}
		}
	}

	writeTrustFile(localPath, &remoteFile)
	_, _ = fmt.Fprintf(os.Stdout, "Trust config updated to version %s (generated %s)\n",
		remoteFile.Version, remoteFile.GeneratedAt)
}

func runTrustExport() {
	effective := loadEffectiveTrust()

	data, err := json.MarshalIndent(effective, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "trust export: marshal error: %v\n", err)
		os.Exit(4)
	}
	fmt.Println(string(data))
}

func runTrustImport(path string) {
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		fmt.Fprintf(os.Stderr, "trust import: read %s: %v\n", path, err)
		os.Exit(4)
	}

	var incoming intel.TrustFile
	if err := json.Unmarshal(data, &incoming); err != nil {
		fmt.Fprintf(os.Stderr, "trust import: invalid trust config: %v\n", err)
		os.Exit(4)
	}

	existing := loadEffectiveTrust()

	merged := mergeTrustFiles(existing, &incoming)

	dir, err := trustConfigDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "trust import: %v\n", err)
		os.Exit(4)
	}

	writeTrustFile(filepath.Join(dir, "trust.json"), merged)
	_, _ = fmt.Fprintf(os.Stdout, "Trust config merged and saved\n")
}

func loadEffectiveTrust() *intel.TrustFile {
	path := config.DefaultTrustPath()
	var result intel.TrustFile

	if path != "" {
		data, err := os.ReadFile(path) //nolint:gosec
		if err == nil {
			_ = json.Unmarshal(data, &result)
		}
	}

	tf, err := intel.LoadDefaults()
	if err != nil {
		return &result
	}

	if len(result.Trusted) == 0 {
		result.Trusted = tf.Trusted
	}
	if len(result.Blocked) == 0 {
		result.Blocked = tf.Blocked
	}
	if result.Version == "" {
		result.Version = tf.Version
		result.GeneratedAt = tf.GeneratedAt
	}
	if result.Servers == nil {
		result.Servers = tf.Servers
	}
	if result.Tools == nil {
		result.Tools = tf.Tools
	}
	if result.PinnedTools == nil {
		result.PinnedTools = tf.PinnedTools
	}

	return &result
}

func mergeStringSlices(base, overlay []string) []string {
	seen := make(map[string]bool, len(base)+len(overlay))
	out := make([]string, 0, len(base)+len(overlay))
	for _, s := range base {
		seen[s] = true
		out = append(out, s)
	}
	for _, s := range overlay {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func mergeTrustFiles(base, overlay *intel.TrustFile) *intel.TrustFile {
	merged := *base

	merged.Trusted = mergeStringSlices(merged.Trusted, overlay.Trusted)
	merged.Blocked = mergeStringSlices(merged.Blocked, overlay.Blocked)

	if overlay.Servers != nil {
		if merged.Servers == nil {
			merged.Servers = make(map[string]intel.Scope)
		}
		for k, v := range overlay.Servers {
			if _, ok := merged.Servers[k]; !ok {
				merged.Servers[k] = v
			}
		}
	}

	if overlay.Tools != nil {
		if merged.Tools == nil {
			merged.Tools = make(map[string]intel.Scope)
		}
		for k, v := range overlay.Tools {
			if _, ok := merged.Tools[k]; !ok {
				merged.Tools[k] = v
			}
		}
	}

	if overlay.PinnedTools != nil {
		if merged.PinnedTools == nil {
			merged.PinnedTools = make(map[string]string)
		}
		for k, v := range overlay.PinnedTools {
			if _, ok := merged.PinnedTools[k]; !ok {
				merged.PinnedTools[k] = v
			}
		}
	}

	return &merged
}

func readYes() bool {
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	line = strings.TrimSpace(line)
	return line == "y" || line == "Y" || line == "yes" || line == "Yes"
}

func promptOverwrite(localPath string, local, remote *intel.TrustFile) {
	fmt.Printf("Local trust config differs from remote.\n")
	fmt.Printf("  Local:  version=%s generated=%s\n", local.Version, local.GeneratedAt)
	fmt.Printf("  Remote: version=%s generated=%s\n", remote.Version, remote.GeneratedAt)
	fmt.Print("Overwrite local config with remote? [y/N]: ")
	if !readYes() {
		fmt.Println("Update cancelled.")
		os.Exit(0)
	}

	writeTrustFile(localPath, remote)
	_, _ = fmt.Fprintf(os.Stdout, "Trust config updated to version %s (generated %s)\n",
		remote.Version, remote.GeneratedAt)
}

func writeTrustFile(path string, tf *intel.TrustFile) {
	data, err := json.MarshalIndent(tf, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "trust: marshal error: %v\n", err)
		os.Exit(4)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "trust: write error: %v\n", err)
		os.Exit(4)
	}
	if err := os.Rename(tmp, path); err != nil {
		fmt.Fprintf(os.Stderr, "trust: rename error: %v\n", err)
		os.Exit(4)
	}
}

func fetchURL(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: HTTP %d", url, resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	return data, nil
}
