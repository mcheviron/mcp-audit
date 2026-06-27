package manifest

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"sort"

	"github.com/mcheviron/mcp-audit/internal/intel"
	"github.com/mcheviron/mcp-audit/internal/report"
	"github.com/mcheviron/mcp-audit/internal/scanner"
)

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

type Manifest struct {
	Version          string `json:"version"`
	Commit           string `json:"commit"`
	BuildDate        string `json:"build_date"`
	GoVersion        string `json:"go_version"`
	TrustListSHA256  string `json:"trust_list_sha256"`
	ProbesListSHA256 string `json:"probes_list_sha256"`
	SchemaJSON       string `json:"schema_json"`
	SchemaSARIF      string `json:"schema_sarif"`
}

func Build() Manifest {
	return Manifest{
		Version:          Version,
		Commit:           Commit,
		BuildDate:        BuildDate,
		GoVersion:        runtime.Version(),
		TrustListSHA256:  hashBytes(intel.DefaultTrustJSON()),
		ProbesListSHA256: hashBytes(scanner.ProbesText()),
		SchemaJSON:       report.SchemaJSON,
		SchemaSARIF:      report.SchemaSARIF,
	}
}

func hashBytes(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (m Manifest) WriteJSON(w io.Writer) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	data = append(data, '\n')
	_, err = w.Write(data)
	return err
}

func (m Manifest) WriteText(w io.Writer) error {
	pairs := [][2]string{
		{"version", m.Version},
		{"commit", m.Commit},
		{"build_date", m.BuildDate},
		{"go_version", m.GoVersion},
		{"trust_list_sha256", m.TrustListSHA256},
		{"probes_list_sha256", m.ProbesListSHA256},
		{"schema_json", m.SchemaJSON},
		{"schema_sarif", m.SchemaSARIF},
	}
	maxKey := 0
	for _, p := range pairs {
		if len(p[0]) > maxKey {
			maxKey = len(p[0])
		}
	}
	for _, p := range pairs {
		if _, err := fmt.Fprintf(w, "%-*s  %s\n", maxKey, p[0], p[1]); err != nil {
			return err
		}
	}
	return nil
}

func ManifestFromFile(path string) (Manifest, error) {
	var m Manifest
	return m, fmt.Errorf("ManifestFromFile: not yet implemented: %s", path)
}

func Keys() []string {
	m := Build()
	keys := make([]string, 0, 8)
	data, err := json.Marshal(m)
	if err != nil {
		return keys
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return keys
	}
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
