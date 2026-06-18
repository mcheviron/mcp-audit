package scanner

import (
	"github.com/mostafaelataby-cheviron/mcp-audit/internal/config"
)

type AuthConfig struct {
	Token   string
	Headers map[string]string
	Cert    string
	Key     string
}

type Scanner struct {
	TrustConfig  *config.TrustConfig
	Probes       []string
	AllowHosts   []string
	BlockHosts   []string
	Transport    string
	AuthToken    string
	AuthHeaders  map[string]string
	TLSCertFile  string
	TLSKeyFile   string
	ToolAnalysis bool

	SnapshotDir       string
	NoSnapshot        bool
	NoTrustOnFirstUse bool

	TestConfigs []config.Config
}

func NewScanner() *Scanner {
	return &Scanner{ToolAnalysis: true}
}

func (s *Scanner) authConfig() AuthConfig {
	return AuthConfig{
		Token:   s.AuthToken,
		Headers: s.AuthHeaders,
		Cert:    s.TLSCertFile,
		Key:     s.TLSKeyFile,
	}
}

func (s *Scanner) discoverConfigs() []config.Config {
	if s.TestConfigs != nil {
		return s.TestConfigs
	}
	return config.Discover()
}

func (s *Scanner) SetTrustConfig(path string) error {
	if path == "" {
		path = config.DefaultTrustPath()
	}
	if path == "" {
		return nil
	}
	tc, err := config.LoadTrust(path)
	if err != nil {
		return err
	}
	s.TrustConfig = tc
	return nil
}
