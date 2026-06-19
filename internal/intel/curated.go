package intel

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"time"
)

//go:embed default-trust.json
var defaultTrustJSON []byte

type TrustFile struct {
	Version     string            `json:"version"`
	GeneratedAt string            `json:"generated_at"`
	Trusted     []string          `json:"trusted,omitempty"`
	Blocked     []string          `json:"blocked,omitempty"`
	Servers     map[string]Scope  `json:"servers,omitempty"`
	Tools       map[string]Scope  `json:"tools,omitempty"`
	PinnedTools map[string]string `json:"pinned_tools,omitempty"`
}

type Scope struct {
	Trusted []string `json:"trusted,omitempty"`
	Blocked []string `json:"blocked,omitempty"`
}

func LoadDefaults() (*TrustFile, error) {
	var tf TrustFile
	if err := json.Unmarshal(defaultTrustJSON, &tf); err != nil {
		return nil, fmt.Errorf("unmarshal embedded trust config: %w", err)
	}
	return &tf, nil
}

func (tf *TrustFile) Age() time.Duration {
	t, err := time.Parse(time.RFC3339, tf.GeneratedAt)
	if err != nil {
		return 0
	}
	return time.Since(t)
}

func (tf *TrustFile) IsStale(maxAge time.Duration) bool {
	return tf.Age() > maxAge
}
