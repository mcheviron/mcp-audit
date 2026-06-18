package snapshot

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"
)

type ToolEntry struct {
	Name            string   `json:"name"`
	DescriptionHash string   `json:"description_hash"`
	SchemaHash      string   `json:"schema_hash"`
	Properties      []string `json:"properties,omitempty"`
}

type Snapshot struct {
	Server    string      `json:"server"`
	Key       string      `json:"key"`
	URL       string      `json:"url,omitempty"`
	Command   string      `json:"command,omitempty"`
	ScannedAt time.Time   `json:"scanned_at"`
	Tools     []ToolEntry `json:"tools"`
}

type DriftType int

const (
	DriftFirstScan DriftType = iota
	DriftToolAdded
	DriftToolRemoved
	DriftDescriptionChanged
	DriftSchemaChanged
	DriftPinnedMismatch
	DriftPinnedMissing
)

type DriftFinding struct {
	Server     string
	Tool       string
	DriftType  DriftType
	Severity   Severity
	Finding    string
	Detail     string
	ConfigPath string
}

func MakeKey(srvName, url, command string) string {
	var parts []string
	if srvName != "" {
		parts = append(parts, sanitize(srvName))
	}
	if url != "" {
		parts = append(parts, sanitize(url))
	}
	if command != "" {
		parts = append(parts, sanitize(command))
	}
	if len(parts) == 0 {
		return "unknown"
	}
	return strings.Join(parts, "|")
}

var sanitizeReplacer = strings.NewReplacer(
	"://", "_",
	"/", "_",
	":", "_",
	"@", "_",
	" ", "_",
	"\\", "_",
)

func sanitize(s string) string {
	return sanitizeReplacer.Replace(s)
}

func HashToolDescription(desc string) string {
	hash := sha256.Sum256([]byte(strings.TrimSpace(desc)))
	return fmt.Sprintf("sha256:%x", hash)
}
