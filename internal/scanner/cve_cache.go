package scanner

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

type cveCacheEntry struct {
	Entries  []CVEEntry `json:"entries"`
	CachedAt time.Time  `json:"cached_at"`
	Package  string     `json:"package"`
}

func cveCacheKey(packageName string) string {
	h := sha256.Sum256([]byte(packageName))
	return fmt.Sprintf("%x", h)
}

func loadCVECache(cacheDir, packageName string, ttlHours int) ([]CVEEntry, bool) {
	if cacheDir == "" {
		return nil, false
	}

	key := cveCacheKey(packageName)
	path := filepath.Join(cacheDir, key+".json")

	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return nil, false
	}

	var entry cveCacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		slog.Debug("cve cache parse error", "path", path, "error", err)
		return nil, false
	}

	if ttlHours <= 0 {
		return entry.Entries, true
	}

	if time.Since(entry.CachedAt) >= time.Duration(ttlHours)*time.Hour {
		return nil, false
	}

	return entry.Entries, true
}

func writeCVECache(cacheDir, packageName string, entries []CVEEntry) error {
	if cacheDir == "" {
		return nil
	}

	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return fmt.Errorf("cve cache mkdir: %w", err)
	}

	key := cveCacheKey(packageName)
	path := filepath.Join(cacheDir, key+".json")
	tmpPath := path + ".tmp"

	entry := cveCacheEntry{
		Entries:  entries,
		CachedAt: time.Now(),
		Package:  packageName,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("cve cache marshal: %w", err)
	}

	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return fmt.Errorf("cve cache write: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		if rerr := os.Remove(tmpPath); rerr != nil {
			slog.Debug("cve cache cleanup", "path", tmpPath, "error", rerr)
		}
		return fmt.Errorf("cve cache rename: %w", err)
	}

	return nil
}
