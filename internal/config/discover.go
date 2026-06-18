package config

import (
	"os"
	"path/filepath"
	"runtime"
)

func init() {
	registry = []ToolParser{
		{
			Name:  "claude",
			Paths: claudePaths,
			Parse: func(data []byte) ([]ServerEntry, error) {
				return parseMcpServers(data, "claude")
			},
		},
		{
			Name: "cursor",
			Paths: func(home string) []string {
				return []string{filepath.Join(home, ".cursor", "mcp.json")}
			},
			Parse: func(data []byte) ([]ServerEntry, error) {
				return parseMcpServers(data, "cursor")
			},
		},
		{
			Name: "windsurf",
			Paths: func(home string) []string {
				return []string{filepath.Join(home, ".codeium", "windsurf", "mcp_config.json")}
			},
			Parse: func(data []byte) ([]ServerEntry, error) {
				return parseMcpServers(data, "windsurf")
			},
		},
		{
			Name: "vscode",
			Paths: func(home string) []string {
				return []string{filepath.Join(home, ".vscode", "mcp.json")}
			},
			Parse: func(data []byte) ([]ServerEntry, error) {
				return parseMcpServers(data, "vscode")
			},
		},
		{
			Name: "continue",
			Paths: func(home string) []string {
				return []string{filepath.Join(home, ".continue", "config.json")}
			},
			Parse: parseContinue,
		},
		{
			Name: "opencode",
			Paths: func(home string) []string {
				return []string{filepath.Join(home, ".config", "opencode", "opencode.json")}
			},
			Parse: parseOpenCode,
		},
	}
}

func Discover() []Config {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	var configs []Config

	for _, tp := range registry {
		for _, path := range tp.Paths(home) {
			cfg := Config{Tool: tp.Name, Path: path}

			data, err := os.ReadFile(path) //nolint:gosec
			if err != nil {
				continue
			}

			cfg.Raw = data

			servers, err := tp.Parse(data)
			if err != nil {
				cfg.Error = err
			}
			for i := range servers {
				servers[i].ConfigPath = path
			}
			cfg.Servers = servers
			configs = append(configs, cfg)

			break
		}
	}

	return configs
}

func claudePaths(home string) []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")}
	case "linux":
		return []string{filepath.Join(home, ".config", "Claude", "claude_desktop_config.json")}
	default:
		return []string{filepath.Join(home, "AppData", "Roaming", "Claude", "claude_desktop_config.json")}
	}
}
