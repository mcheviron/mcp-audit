package scanner

import (
	"log/slog"
	"maps"
	"sync"
	"time"

	"github.com/mcheviron/mcp-audit/internal/config"
	"github.com/mcheviron/mcp-audit/internal/intel"
	"github.com/mcheviron/mcp-audit/internal/mcp"
)

const embeddedTrustStaleness = 90 * 24 * time.Hour

func New(cfg ScannerConfig) *Scanner {
	return &Scanner{ScannerConfig: cfg, LastProbeTools: map[string][]mcp.Tool{}}
}

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

type CallbackListener struct {
	Port     int
	Callback chan string
	Results  []Result
	mu       sync.Mutex
	done     chan struct{}
}

type SnapshotConfig struct {
	Dir               string
	Disabled          bool
	NoTrustOnFirstUse bool
	NoSecretScan      bool
}

type ProbeConfig struct {
	Depth           ProbeDepth
	CallbackPort    int
	TargetsFile     string
	MaxResponseSize int
	TimeoutSecs     int
	Concurrency     int
}

type CVEConfig struct {
	Disabled    bool
	CacheDir    string
	CacheTTLHrs int
}

type HeuristicConfig struct {
	Enabled          bool
	ScoreWeights     Weights
	MinSecurityScore float64
	MaxAbsoluteRisk  float64
}

type AdversarialConfig struct {
	Enabled   bool
	MaxProbes int
}

type CrossServerConfig struct {
	Enabled bool
}

type ScannerConfig struct {
	Trust        *config.TrustConfig
	Probes       []string
	AllowHosts   []string
	BlockHosts   []string
	Transport    string
	Auth         AuthConfig
	ToolAnalysis bool
	Snapshot     SnapshotConfig
	Probe        ProbeConfig
	CrossServer  CrossServerConfig
	CVE          CVEConfig
	ProjectDir   string
	Heuristic    HeuristicConfig
	Adversarial  AdversarialConfig
}

type Scanner struct {
	ScannerConfig
	LastProbeTools map[string][]mcp.Tool
	TestConfigs    []config.Config
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
	s.Trust = tc
	return nil
}

func (s *Scanner) authConfig() AuthConfig {
	return s.Auth
}

func (s *Scanner) discoverConfigs() []config.Config {
	if s.TestConfigs != nil {
		return s.TestConfigs
	}
	return config.Discover(s.ProjectDir)
}

func (s *Scanner) loadEmbeddedDefaults() error {
	tf, err := intel.LoadDefaults()
	if err != nil {
		return err
	}
	s.Trust = &config.TrustConfig{
		TrustScope: config.TrustScope{
			Trusted: tf.Trusted,
			Blocked: tf.Blocked,
		},
		Servers:     make(map[string]config.TrustScope),
		Tools:       make(map[string]config.TrustScope),
		PinnedTools: make(map[string]string),
	}
	for k, v := range tf.Servers {
		s.Trust.Servers[k] = config.TrustScope{Trusted: v.Trusted, Blocked: v.Blocked}
	}
	for k, v := range tf.Tools {
		s.Trust.Tools[k] = config.TrustScope{Trusted: v.Trusted, Blocked: v.Blocked}
	}
	maps.Copy(s.Trust.PinnedTools, tf.PinnedTools)
	if tf.IsStale(embeddedTrustStaleness) {
		slog.Warn("embedded trust config is over 90 days old, consider running 'mcp-audit trust update'",
			"age", tf.Age().String())
	}
	return nil
}
