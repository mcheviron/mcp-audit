package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type TrustScope struct {
	Trusted []string `json:"trusted,omitempty"`
	Blocked []string `json:"blocked,omitempty"`
}

type TrustConfig struct {
	TrustScope
	Tools   map[string]TrustScope `json:"tools,omitempty"`
	Servers map[string]TrustScope `json:"servers,omitempty"`
}

func LoadTrust(path string) (*TrustConfig, error) {
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("read trust config: %w", err)
	}

	var cfg TrustConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse trust config: %w", err)
	}

	return &cfg, nil
}

func DefaultTrustPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "mcp-audit", "trust.json")
}

func (tc *TrustConfig) ScopeFor(serverName, toolName string) TrustScope {
	if ts, ok := tc.Servers[serverName]; ok {
		return ts
	}
	if ts, ok := tc.Tools[toolName]; ok {
		return ts
	}
	return tc.TrustScope
}
