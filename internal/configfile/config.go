package configfile

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
)

type Config struct {
	Format      string `json:"format"`
	TrustConfig string `json:"trust_config"`
	Targets     string `json:"targets"`
	AllowHosts  string `json:"allow_hosts"`
	BlockHosts  string `json:"block_hosts"`
	Timeout     int    `json:"timeout"`
	Concurrency int    `json:"concurrency"`
	ProbeDepth  string `json:"probe_depth"`
	MaxResponse int    `json:"max_response"`
	NoColor     bool   `json:"no_color"`
	SnapshotDir string `json:"snapshot_dir"`
}

func LoadPath(path string) *Config {
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return &Config{}
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		slog.Warn("config parse error", "path", path, "error", err)
		return &Config{}
	}

	return &cfg
}

func Load() *Config {
	home, err := os.UserHomeDir()
	if err != nil {
		return &Config{}
	}
	path := filepath.Join(home, ".config", "mcp-audit", "config.json")
	return LoadPath(path)
}
