package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/go-set"
	"github.com/mostafaelataby-cheviron/mcp-audit/internal/config"
	"github.com/mostafaelataby-cheviron/mcp-audit/internal/intel"
)

var errUserCancelled = errors.New("update cancelled by user")

var trustUpdateURL = "https://github.com/mcp-audit-db/releases/latest/download/trust.json"
var trustChecksumURL = "https://github.com/mcp-audit-db/releases/latest/download/trust.json.sha256"

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

func runTrustUpdate() error {
	dir, err := trustConfigDir()
	if err != nil {
		return &exitError{code: 4, err: fmt.Errorf("trust update: %w", err)}
	}

	remoteData, err := fetchURL(trustUpdateURL)
	if err != nil {
		return &exitError{code: 4, err: fmt.Errorf("trust update: failed to fetch latest trust config: %w", err)}
	}

	checksumData, checksumErr := fetchURL(trustChecksumURL)
	if checksumErr != nil {
		fmt.Fprintf(os.Stderr, "trust update: warning: checksum file unavailable, proceeding without verification\n")
	} else {
		if err := verifyChecksum(remoteData, checksumData); err != nil {
			return &exitError{code: 4, err: fmt.Errorf("trust update: checksum verification failed: %w", err)}
		}
	}

	var remoteFile intel.TrustFile
	if err := json.Unmarshal(remoteData, &remoteFile); err != nil {
		return &exitError{code: 4, err: fmt.Errorf("trust update: invalid remote trust config: %w", err)}
	}

	localPath := filepath.Join(dir, "trust.json")
	if data, err := os.ReadFile(localPath); err == nil { //nolint:gosec
		var localFile intel.TrustFile
		if json.Unmarshal(data, &localFile) == nil {
			if localFile.Version != remoteFile.Version || localFile.GeneratedAt != remoteFile.GeneratedAt {
				if err := promptOverwrite(localPath, &localFile, &remoteFile); err != nil {
					if errors.Is(err, errUserCancelled) {
						return nil
					}
					return err
				}
				return nil
			}
		}
	}

	if err := writeTrustFile(localPath, &remoteFile); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(os.Stdout, "Trust config updated to version %s (generated %s)\n",
		remoteFile.Version, remoteFile.GeneratedAt)
	return nil
}

func verifyChecksum(data []byte, checksumFile []byte) error {
	expected := sha256.Sum256(data)
	expectedHex := hex.EncodeToString(expected[:])

	entry := strings.TrimSpace(string(checksumFile))
	if entry == "" {
		return nil
	}

	parts := strings.Fields(entry)
	if len(parts) < 1 {
		return fmt.Errorf("invalid checksum file format")
	}
	checksumHex := strings.TrimSpace(parts[0])

	if !strings.EqualFold(expectedHex, checksumHex) {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedHex, checksumHex)
	}
	return nil
}

func runTrustExport() error {
	effective := loadEffectiveTrust()

	data, err := json.MarshalIndent(effective, "", "  ")
	if err != nil {
		return &exitError{code: 4, err: fmt.Errorf("trust export: marshal error: %w", err)}
	}
	fmt.Println(string(data))
	return nil
}

func runTrustImport(path string) error {
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return &exitError{code: 4, err: fmt.Errorf("trust import: read %s: %w", path, err)}
	}

	var incoming intel.TrustFile
	if err := json.Unmarshal(data, &incoming); err != nil {
		return &exitError{code: 4, err: fmt.Errorf("trust import: invalid trust config: %w", err)}
	}

	existing := loadEffectiveTrust()

	merged := mergeTrustFiles(existing, &incoming)

	dir, err := trustConfigDir()
	if err != nil {
		return &exitError{code: 4, err: fmt.Errorf("trust import: %w", err)}
	}

	if err := writeTrustFile(filepath.Join(dir, "trust.json"), merged); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(os.Stdout, "Trust config merged and saved\n")
	return nil
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
	seen := set.New[string](len(base) + len(overlay))
	out := make([]string, 0, len(base)+len(overlay))
	for _, s := range base {
		seen.Insert(s)
		out = append(out, s)
	}
	for _, s := range overlay {
		if !seen.Contains(s) {
			seen.Insert(s)
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

func promptOverwrite(localPath string, local, remote *intel.TrustFile) error {
	fmt.Printf("Local trust config differs from remote.\n")
	fmt.Printf("  Local:  version=%s generated=%s\n", local.Version, local.GeneratedAt)
	fmt.Printf("  Remote: version=%s generated=%s\n", remote.Version, remote.GeneratedAt)
	fmt.Print("Overwrite local config with remote? [y/N]: ")
	if !readYes() {
		fmt.Println("Update cancelled.")
		return errUserCancelled
	}

	if err := writeTrustFile(localPath, remote); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(os.Stdout, "Trust config updated to version %s (generated %s)\n",
		remote.Version, remote.GeneratedAt)
	return nil
}

func writeTrustFile(path string, tf *intel.TrustFile) error {
	data, err := json.MarshalIndent(tf, "", "  ")
	if err != nil {
		return &exitError{code: 4, err: fmt.Errorf("trust: marshal error: %w", err)}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return &exitError{code: 4, err: fmt.Errorf("trust: write error: %w", err)}
	}
	if err := os.Rename(tmp, path); err != nil {
		return &exitError{code: 4, err: fmt.Errorf("trust: rename error: %w", err)}
	}
	return nil
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
