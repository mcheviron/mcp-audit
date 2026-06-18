package config

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

func parseMcpServers(data []byte, tool string) ([]ServerEntry, error) {
	var wrapper struct {
		McpServers map[string]struct {
			Command string         `json:"command"`
			Args    []string       `json:"args"`
			URL     string         `json:"url"`
			Headers map[string]any `json:"headers"`
			Env     map[string]any `json:"env"`
			Token   string         `json:"token"`
			TLS     *struct {
				Cert string `json:"cert"`
				Key  string `json:"key"`
			} `json:"tls"`
		} `json:"mcpServers"`
	}

	if err := json.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("invalid config JSON: %w", err)
	}

	var servers []ServerEntry
	for name, s := range wrapper.McpServers {
		headers := coerceMap(s.Headers)
		entry := ServerEntry{
			Name:        name,
			Tool:        tool,
			URL:         s.URL,
			Args:        s.Args,
			Command:     s.Command,
			AuthHeaders: headers,
			Headers:     headers,
			Env:         coerceMap(s.Env),
			AuthToken:   s.Token,
		}
		if s.TLS != nil {
			entry.TLSCertFile = s.TLS.Cert
			entry.TLSKeyFile = s.TLS.Key
		}

		switch {
		case s.URL != "":
			entry.Transport = "http"
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

func parseContinue(data []byte) ([]ServerEntry, error) {
	var wrapper struct {
		Experimental struct {
			Servers []struct {
				Transport struct {
					Type    string         `json:"type"`
					Command string         `json:"command"`
					Args    []string       `json:"args"`
					URL     string         `json:"url"`
					Headers map[string]any `json:"headers"`
					Env     map[string]any `json:"env"`
				} `json:"transport"`
			} `json:"modelContextProtocolServers"`
		} `json:"experimental"`
	}

	if err := json.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("invalid continue config JSON: %w", err)
	}

	var servers []ServerEntry
	for i, s := range wrapper.Experimental.Servers {
		headers := coerceMap(s.Transport.Headers)
		entry := ServerEntry{
			Name:        fmt.Sprintf("continue-server-%d", i),
			Tool:        "continue",
			Command:     s.Transport.Command,
			Args:        s.Transport.Args,
			URL:         s.Transport.URL,
			Headers:     headers,
			AuthHeaders: headers,
			Env:         coerceMap(s.Transport.Env),
		}

		switch {
		case s.Transport.URL != "":
			entry.Transport = "http"
		case s.Transport.Command != "":
			entry.Transport = "stdio"
		default:
			continue
		}

		entry.Package = extractPackage(s.Transport.Command, s.Transport.Args)

		servers = append(servers, entry)
	}

	return servers, nil
}

func parseOpenCode(data []byte) ([]ServerEntry, error) {
	var wrapper struct {
		Mcp map[string]struct {
			Type    string         `json:"type"`
			Command []string       `json:"command"`
			URL     string         `json:"url"`
			Enabled bool           `json:"enabled"`
			Headers map[string]any `json:"headers"`
			Env     map[string]any `json:"env"`
		} `json:"mcp"`
	}

	if err := json.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("invalid opencode config JSON: %w", err)
	}

	var servers []ServerEntry
	for name, s := range wrapper.Mcp {
		headers := coerceMap(s.Headers)
		entry := ServerEntry{
			Name:        name,
			Tool:        "opencode",
			URL:         s.URL,
			Headers:     headers,
			AuthHeaders: headers,
			Env:         coerceMap(s.Env),
		}

		if len(s.Command) > 0 {
			entry.Command = s.Command[0]
			if len(s.Command) > 1 {
				entry.Args = s.Command[1:]
			}
		}

		switch {
		case s.Type == "remote" && s.URL != "":
			entry.Transport = "http"
		case s.Type == "local" && entry.Command != "":
			entry.Transport = "stdio"
		default:
			continue
		}

		entry.Package = extractPackage(entry.Command, entry.Args)

		servers = append(servers, entry)
	}

	return servers, nil
}

var runners = map[string]bool{
	"npx": true, "npm": true, "npm exec": true,
	"uvx": true, "uv": true, "uv run": true,
	"pipx": true, "pipx run": true,
}

func coerceMap(in map[string]any) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = coerceValue(v)
	}
	return out
}

func coerceValue(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}

func extractPackage(command string, args []string) string {
	if runners[command] {
		for _, a := range args {
			if a == "run" {
				continue
			}
			if !strings.HasPrefix(a, "-") && a != "" {
				return a
			}
		}
		return ""
	}

	if command == "go" && len(args) > 0 && args[0] == "run" {
		if len(args) > 1 && !strings.HasPrefix(args[1], "-") {
			return args[1]
		}
		return ""
	}

	if strings.HasPrefix(command, "/") {
		return ""
	}

	if strings.Contains(command, "/") || strings.Contains(command, "@") {
		return command
	}

	if len(args) == 0 {
		return command
	}

	for _, a := range args {
		if !strings.HasPrefix(a, "-") && a != "" {
			return a
		}
	}

	return ""
}
