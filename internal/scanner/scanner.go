package scanner

import (
	"log/slog"
	"maps"
	"sync"
	"time"

	"github.com/mostafaelataby-cheviron/mcp-audit/internal/config"
	"github.com/mostafaelataby-cheviron/mcp-audit/internal/intel"
)

type AuthConfig struct {
	Token   string
	Headers map[string]string
	Cert    string
	Key     string
}

type ProbeDepth int

const (
	DepthBasic ProbeDepth = iota
	DepthExtended
	DepthFull
)

func (d ProbeDepth) String() string {
	switch d {
	case DepthBasic:
		return "basic"
	case DepthExtended:
		return "extended"
	case DepthFull:
		return "full"
	default:
		return "basic"
	}
}

func ParseProbeDepth(s string) ProbeDepth {
	switch s {
	case "extended":
		return DepthExtended
	case "full":
		return DepthFull
	default:
		return DepthBasic
	}
}

type CallbackListener struct {
	Port     int
	Callback chan string
	Results  []Result
	mu       sync.Mutex
	done     chan struct{}
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
	NoSecretScan      bool

	ProbeDepth      ProbeDepth
	CallbackPort    int
	TargetsFile     string
	MaxResponseSize int
	TimeoutSecs     int
	Concurrency     int

	CrossServerAnalysis bool

	TestConfigs []config.Config
}

const embeddedTrustStaleness = 90 * 24 * time.Hour

func NewScanner() *Scanner {
	return &Scanner{ToolAnalysis: true, CrossServerAnalysis: true, MaxResponseSize: 65536}
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
	userSpecified := path != ""
	if path == "" {
		path = config.DefaultTrustPath()
	}
	if path == "" {
		return s.loadEmbeddedDefaults()
	}
	tc, err := config.LoadTrust(path)
	if err != nil {
		if userSpecified {
			return err
		}
		slog.Debug("no user trust config, falling back to embedded defaults", "error", err)
		return s.loadEmbeddedDefaults()
	}
	s.TrustConfig = tc
	return nil
}

func (s *Scanner) loadEmbeddedDefaults() error {
	tf, err := intel.LoadDefaults()
	if err != nil {
		return err
	}
	s.TrustConfig = &config.TrustConfig{
		TrustScope: config.TrustScope{
			Trusted: tf.Trusted,
			Blocked: tf.Blocked,
		},
		Servers:     make(map[string]config.TrustScope),
		Tools:       make(map[string]config.TrustScope),
		PinnedTools: make(map[string]string),
	}
	for k, v := range tf.Servers {
		s.TrustConfig.Servers[k] = config.TrustScope{Trusted: v.Trusted, Blocked: v.Blocked}
	}
	for k, v := range tf.Tools {
		s.TrustConfig.Tools[k] = config.TrustScope{Trusted: v.Trusted, Blocked: v.Blocked}
	}
	maps.Copy(s.TrustConfig.PinnedTools, tf.PinnedTools)
	if tf.IsStale(embeddedTrustStaleness) {
		slog.Warn("embedded trust config is over 90 days old, consider running 'mcp-audit trust update'",
			"age", tf.Age().String())
	}
	return nil
}
