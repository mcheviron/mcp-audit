package config

type ServerEntry struct {
	Name        string
	Transport   string
	Command     string
	Args        []string
	URL         string
	Package     string
	Tool        string
	ConfigPath  string
	AuthHeaders map[string]string
	AuthToken   string
	TLSCertFile string
	TLSKeyFile  string
	Env         map[string]string
	Headers     map[string]string
	Scope       string
}

type TransportKind int

const (
	TransportStdio TransportKind = iota + 1
	TransportHTTP
	TransportSSE
)

func (s ServerEntry) Kind() TransportKind {
	switch s.Transport {
	case "http":
		return TransportHTTP
	case "stdio":
		return TransportStdio
	case "sse":
		return TransportSSE
	default:
		return 0
	}
}

type Config struct {
	Tool    string
	Path    string
	Servers []ServerEntry
	Error   error
	Raw     []byte
	Scope   string
}

type ToolParserFormat string

const (
	FormatJSON ToolParserFormat = "json"
	FormatTOML ToolParserFormat = "toml"
)

type ToolParser struct {
	Name   string
	Format ToolParserFormat
	Paths  func(home string) []string
	Parse  func(data []byte) ([]ServerEntry, error)
}

var registry []ToolParser

func RegisterTool(tp ToolParser) {
	registry = append(registry, tp)
}

func Registry() []ToolParser {
	return registry
}
