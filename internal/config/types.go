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
}

type ToolParser struct {
	Name  string
	Paths func(home string) []string
	Parse func(data []byte) ([]ServerEntry, error)
}

var registry []ToolParser
