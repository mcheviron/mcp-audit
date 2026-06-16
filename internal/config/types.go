package config

type ServerEntry struct {
	Name       string
	Transport  string
	Command    string
	Args       []string
	URL        string
	Package    string
	Tool       string
	ConfigPath string
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
