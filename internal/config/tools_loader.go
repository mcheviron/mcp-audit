package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

type userToolDef struct {
	Name      string   `json:"name"`
	Format    string   `json:"format"`
	ServerKey string   `json:"server_key"`
	Paths     []string `json:"paths"`
}

type userToolsFile struct {
	Tools []userToolDef `json:"tools"`
}

func LoadUserTools(path string) ([]ToolParser, error) {
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		slog.Warn("failed to read user tools config", "path", path, "error", err)
		return nil, nil
	}

	var file userToolsFile
	if err := json.Unmarshal(data, &file); err != nil {
		slog.Warn("malformed user tools config, using built-in tools only", "path", path, "error", err)
		return nil, nil
	}

	home := ""
	if h, err := os.UserHomeDir(); err == nil {
		home = h
	}

	var tools []ToolParser
	for _, def := range file.Tools {
		if def.Name == "" {
			continue
		}

		tp := ToolParser{
			Name:   def.Name,
			Format: ToolParserFormat(def.Format),
			Paths:  buildPathsFunc(def.Paths, home),
		}

		if def.Format == "" {
			tp.Format = FormatJSON
		}

		tools = append(tools, tp)
	}

	return tools, nil
}

func MergeUserTools(userTools []ToolParser) {
	if len(userTools) == 0 {
		return
	}

	builtinByName := make(map[string]int)
	for i, tp := range registry {
		builtinByName[tp.Name] = i
	}

	for _, ut := range userTools {
		if idx, exists := builtinByName[ut.Name]; exists {
			slog.Warn(fmt.Sprintf("user tool %q overrides built-in tool", ut.Name))
			registry[idx] = ut
		} else {
			registry = append(registry, ut)
		}
	}
}

func buildPathsFunc(paths []string, home string) func(string) []string {
	return func(_ string) []string {
		resolved := make([]string, len(paths))
		for i, p := range paths {
			switch {
			case strings.HasPrefix(p, "~/"), strings.HasPrefix(p, `~\`):
				resolved[i] = filepath.Join(home, p[2:])
			case filepath.IsAbs(p):
				resolved[i] = p
			default:
				resolved[i] = filepath.Join(home, p)
			}
		}
		return resolved
	}
}
