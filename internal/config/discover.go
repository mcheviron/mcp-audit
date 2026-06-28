package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/hashicorp/go-set"
)

var registryInitialized bool

func init() {
	initRegistry()
}

func InitRegistry(toolsConfigPath string) {
	initRegistry()
	if toolsConfigPath == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			toolsConfigPath = filepath.Join(home, ".config", "mcp-audit", "tools.json")
		}
	}
	userTools, err := LoadUserTools(toolsConfigPath)
	if err != nil {
		return
	}
	MergeUserTools(userTools)
}

func Discover(cwd string) []Config {
	global, home := discoverGlobal()
	if cwd == "" {
		return global
	}
	project := discoverProject(cwd, home)
	return mergeConfigs(project, global)
}

func initRegistry() {
	if registryInitialized {
		return
	}
	registryInitialized = true
	registry = []ToolParser{
		makeClaudeParser(),
		makeCursorParser(),
		makeWindsurfParser(),
		makeVSCodeParser(),
		makeContinueParser(),
		makeOpenCodeParser(),
		makeCopilotCLIParser(),
		makeClaudeCodeParser(),
		makeCodexParser(),
		makeGeminiParser(),
		makeClineRooParser(),
		makeZedParser(),
	}
}

func makeJSONMCPServersParser(name string, paths func(string) []string) ToolParser {
	return ToolParser{
		Name:   name,
		Format: FormatJSON,
		Paths:  paths,
		Parse: func(data []byte) ([]ServerEntry, error) {
			return parseMCPServers(data, name)
		},
	}
}

func makeClaudeParser() ToolParser {
	return makeJSONMCPServersParser("claude", claudePaths)
}

func makeCursorParser() ToolParser {
	return makeJSONMCPServersParser("cursor", func(home string) []string {
		return []string{filepath.Join(home, ".cursor", "mcp.json")}
	})
}

func makeWindsurfParser() ToolParser {
	return makeJSONMCPServersParser("windsurf", func(home string) []string {
		return []string{filepath.Join(home, ".codeium", "windsurf", "mcp_config.json")}
	})
}

func makeVSCodeParser() ToolParser {
	return makeJSONMCPServersParser("vscode", func(home string) []string {
		return []string{filepath.Join(home, ".vscode", "mcp.json")}
	})
}

func makeContinueParser() ToolParser {
	return ToolParser{
		Name:   "continue",
		Format: FormatJSON,
		Paths: func(home string) []string {
			return []string{filepath.Join(home, ".continue", "config.json")}
		},
		Parse: parseContinue,
	}
}

func makeOpenCodeParser() ToolParser {
	return ToolParser{
		Name:   "opencode",
		Format: FormatJSON,
		Paths: func(home string) []string {
			return []string{filepath.Join(home, ".config", "opencode", "opencode.json")}
		},
		Parse: parseOpenCode,
	}
}

func makeCopilotCLIParser() ToolParser {
	return makeJSONMCPServersParser("copilot-cli", func(home string) []string {
		return []string{filepath.Join(home, ".copilot", "mcp-config.json")}
	})
}

func makeClaudeCodeParser() ToolParser {
	return makeJSONMCPServersParser("claude-code", claudeCodePaths)
}

func makeCodexParser() ToolParser {
	return ToolParser{
		Name:   "codex",
		Format: FormatTOML,
		Paths:  codexPaths,
	}
}

func makeGeminiParser() ToolParser {
	return ToolParser{
		Name:   "gemini",
		Format: FormatJSON,
		Paths:  geminiPaths,
		Parse:  parseGeminiSettings,
	}
}

func makeClineRooParser() ToolParser {
	return makeJSONMCPServersParser("cline-roo", clineRooPaths)
}

func makeZedParser() ToolParser {
	return ToolParser{
		Name:   "zed",
		Format: FormatJSON,
		Paths: func(home string) []string {
			return []string{filepath.Join(home, ".config", "zed", "settings.json")}
		},
		Parse: parseZedSettings,
	}
}

func walkProjectConfigs(cwd string, tp ToolParser, home string) ([]string, error) {
	if cwd == "" {
		return nil, nil
	}
	abs, err := filepath.Abs(cwd)
	if err != nil {
		return nil, err
	}
	dir := abs
	for {
		var found []string
		for _, p := range tp.Paths("") {
			candidate := filepath.Join(dir, p)
			if _, err := os.Stat(candidate); err == nil {
				found = append(found, candidate)
			}
		}
		if len(found) > 0 {
			return found, nil
		}
		if home != "" && dir == home {
			return nil, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil, nil
		}
		if home != "" && strings.HasPrefix(home, dir+string(filepath.Separator)) {
			return nil, nil
		}
		dir = parent
	}
}

func readConfig(path string, tp ToolParser, scope string) Config {
	cfg := Config{Tool: tp.Name, Path: path, Scope: scope}

	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return cfg
	}

	cfg.Raw = data

	parseFn := resolveParser(tp.Format, tp.Parse)
	servers, err := parseFn(data)
	if err != nil {
		cfg.Error = err
	}
	for i := range servers {
		servers[i].ConfigPath = path
		servers[i].Scope = scope
	}
	cfg.Servers = servers
	return cfg
}

func readConfigIfNew(path string, tp ToolParser, scope string, seen *set.Set[string]) (Config, bool) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return Config{}, false
	}
	if seen.Contains(abs) {
		return Config{}, false
	}
	seen.Insert(abs)

	cfg := readConfig(path, tp, scope)
	if cfg.Raw == nil {
		return Config{}, false
	}
	return cfg, true
}

func discoverGlobal() ([]Config, string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, ""
	}

	var configs []Config
	seen := set.New[string](0)

	for _, tp := range registry {
		for _, path := range tp.Paths(home) {
			if !filepath.IsAbs(path) {
				continue
			}
			cfg, ok := readConfigIfNew(path, tp, "global", seen)
			if !ok {
				continue
			}
			configs = append(configs, cfg)
			break
		}
	}

	return configs, home
}

func discoverProject(cwd, home string) []Config {
	seen := set.New[string](0)

	var configs []Config
	for _, tp := range registry {
		paths, err := walkProjectConfigs(cwd, tp, home)
		if err != nil || len(paths) == 0 {
			continue
		}
		for _, path := range paths {
			cfg, ok := readConfigIfNew(path, tp, "project", seen)
			if !ok {
				continue
			}
			configs = append(configs, cfg)
		}
	}
	return configs
}

func mergeConfigs(project, global []Config) []Config {
	projectByTool := make(map[string]*set.Set[string])
	for _, cfg := range project {
		if projectByTool[cfg.Tool] == nil {
			projectByTool[cfg.Tool] = set.New[string](0)
		}
		for _, srv := range cfg.Servers {
			projectByTool[cfg.Tool].Insert(srv.Name)
		}
	}

	var merged []Config
	merged = append(merged, project...)

	for _, gcfg := range global {
		pNames := projectByTool[gcfg.Tool]
		filtered := make([]ServerEntry, 0, len(gcfg.Servers))
		hasProject := false
		for _, srv := range gcfg.Servers {
			if pNames != nil && pNames.Contains(srv.Name) {
				hasProject = true
				continue
			}
			filtered = append(filtered, srv)
		}
		if len(filtered) == 0 && hasProject {
			continue
		}
		if len(filtered) == 0 {
			hasAny := false
			for _, srv := range gcfg.Servers {
				if srv.Scope == "project" {
					hasAny = true
					break
				}
			}
			if !hasAny {
				merged = append(merged, gcfg)
			}
			continue
		}
		gcfg.Servers = filtered
		merged = append(merged, gcfg)
	}

	for i := range merged {
		hasProject := false
		hasGlobal := false
		for _, srv := range merged[i].Servers {
			if srv.Scope == "project" {
				hasProject = true
			} else {
				hasGlobal = true
			}
		}
		if hasProject {
			merged[i].Scope = "project"
		} else if hasGlobal {
			merged[i].Scope = "global"
		}
	}

	return merged
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

func codexPaths(home string) []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{filepath.Join(home, "Library", "Application Support", "Codex", "config.toml")}
	case "linux":
		return []string{filepath.Join(home, ".codex", "config.toml")}
	default:
		return []string{filepath.Join(home, ".codex", "config.toml")}
	}
}

func claudeCodePaths(home string) []string {
	return []string{
		".mcp.json",
		filepath.Join(home, ".claude", "mcp.json"),
	}
}

func geminiPaths(home string) []string {
	return []string{
		".mcp.json",
		filepath.Join(home, ".gemini", "settings.json"),
	}
}

func clineRooPaths(home string) []string {
	var base string
	switch runtime.GOOS {
	case "darwin":
		base = filepath.Join(home, "Library", "Application Support")
	case "linux":
		base = filepath.Join(home, ".config")
	default:
		base = filepath.Join(home, "AppData", "Roaming")
	}
	rel := filepath.Join("Code", "User", "globalStorage",
		"saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json")
	return []string{filepath.Join(base, rel)}
}
