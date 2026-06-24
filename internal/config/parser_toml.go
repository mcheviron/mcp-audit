package config

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

func parseCodexToml(data []byte) ([]ServerEntry, error) {
	var wrapper struct {
		McpServers map[string]struct {
			Command           string            `toml:"command"`
			Args              []string          `toml:"args"`
			URL               string            `toml:"url"`
			BearerTokenEnvVar string            `toml:"bearer_token_env_var"`
			HTTPHeaders       map[string]string `toml:"http_headers"`
			Env               map[string]string `toml:"env"`
			TLSCertFile       string            `toml:"tls_cert_file"`
			TLSKeyFile        string            `toml:"tls_key_file"`
		} `toml:"mcp_servers"`
	}

	if err := toml.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("invalid TOML config: %w", err)
	}

	var servers []ServerEntry
	for name, s := range wrapper.McpServers {
		entry := ServerEntry{
			Name:    name,
			Tool:    "codex",
			URL:     s.URL,
			Args:    s.Args,
			Command: s.Command,
			Headers: s.HTTPHeaders,
			Env:     s.Env,
		}

		if s.TLSCertFile != "" {
			entry.TLSCertFile = s.TLSCertFile
		}
		if s.TLSKeyFile != "" {
			entry.TLSKeyFile = s.TLSKeyFile
		}

		if s.BearerTokenEnvVar != "" {
			entry.AuthToken = os.Getenv(s.BearerTokenEnvVar)
		}

		if s.HTTPHeaders != nil {
			entry.AuthHeaders = s.HTTPHeaders
		}

		switch {
		case s.URL != "":
			entry.Transport = "sse"
		case s.Command != "":
			entry.Transport = "stdio"
		default:
			continue
		}

		entry.Package = extractPackage(s.Command, s.Args)

		servers = append(servers, entry)
	}

	return servers, nil
}

func resolveParser(
	format ToolParserFormat,
	parseFn func([]byte) ([]ServerEntry, error),
) func([]byte) ([]ServerEntry, error) {
	if parseFn != nil {
		return parseFn
	}
	switch strings.ToLower(string(format)) {
	case "toml":
		return parseCodexToml
	case "json", "":
		return func(data []byte) ([]ServerEntry, error) {
			return parseMCPServers(data, "")
		}
	default:
		slog.Debug("no parser registered for tool format", "format", format)
		return func(data []byte) ([]ServerEntry, error) {
			return nil, fmt.Errorf("unknown tool format: %q", format)
		}
	}
}
