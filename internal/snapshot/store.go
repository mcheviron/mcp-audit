package snapshot

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func DefaultSnapshotDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "mcp-audit", "snapshots")
}

func resolveDir(dir string) string {
	if dir != "" {
		return dir
	}
	return DefaultSnapshotDir()
}

func ensureDir(path string) error {
	return os.MkdirAll(path, 0700)
}

func snapshotPath(dir, key string) string {
	return filepath.Join(dir, key+".json")
}

func SaveSnapshot(dir, key, srvName, url, command string, tools []ToolEntry) error {
	dir = resolveDir(dir)
	if err := ensureDir(dir); err != nil {
		return fmt.Errorf("create snapshot directory %s: %w", dir, err)
	}

	snap := Snapshot{
		Server:    srvName,
		Key:       key,
		URL:       url,
		Command:   command,
		ScannedAt: time.Now(),
		Tools:     tools,
	}

	if snap.Tools == nil {
		snap.Tools = []ToolEntry{}
	}

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}

	path := snapshotPath(dir, key)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write snapshot: %w", err)
	}
	return os.Rename(tmp, path)
}

func LoadSnapshot(dir, key string) (*Snapshot, error) {
	dir = resolveDir(dir)
	path := snapshotPath(dir, key)

	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("read snapshot %s: %w", path, err)
	}

	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("unmarshal snapshot: %w", err)
	}

	return &snap, nil
}
