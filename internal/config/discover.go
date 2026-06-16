package config

import (
	"os"
	"path/filepath"
	"runtime"
)

type toolPath struct {
	Tool string
	Path string
}

func Discover() []Config {
	var configs []Config

	for _, tp := range defaultPaths() {
		cfg := Config{Tool: tp.Tool, Path: tp.Path}

		data, err := os.ReadFile(tp.Path)
		if err != nil {
			continue
		}

		servers, err := parseConfig(tp.Tool, data)
		if err != nil {
			cfg.Error = err
		}
		cfg.Servers = servers
		configs = append(configs, cfg)
	}

	return configs
}

func defaultPaths() []toolPath {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	paths := []toolPath{
		{"claude", claudeDesktopPath(home)},
		{"cursor", filepath.Join(home, ".cursor", "mcp.json")},
		{"windsurf", filepath.Join(home, ".codeium", "windsurf", "mcp_config.json")},
		{"vscode", filepath.Join(home, ".vscode", "mcp.json")},
		{"continue", filepath.Join(home, ".continue", "config.json")},
		{"opencode", filepath.Join(home, ".config", "opencode", "opencode.json")},
	}

	return paths
}

func claudeDesktopPath(home string) string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
	case "linux":
		return filepath.Join(home, ".config", "Claude", "claude_desktop_config.json")
	default:
		return filepath.Join(home, "AppData", "Roaming", "Claude", "claude_desktop_config.json")
	}
}
