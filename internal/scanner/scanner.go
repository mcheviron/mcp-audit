package scanner

import (
	"github.com/mostafaelataby-cheviron/mcp-audit/internal/config"
)

type Scanner struct {
	TrustConfig *config.TrustConfig
	Probes      []string
	AllowHosts  []string
	BlockHosts  []string
}

func NewScanner() *Scanner {
	return &Scanner{}
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
