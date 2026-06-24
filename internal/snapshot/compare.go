package snapshot

import (
	"fmt"
	"time"

	"github.com/hashicorp/go-set"
)

type Severity int

const (
	SevPass Severity = iota
	SevInfo
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevPass:
		return "PASS"
	case SevInfo:
		return "INFO"
	case SevLow:
		return "LOW"
	case SevMedium:
		return "MEDIUM"
	case SevHigh:
		return "HIGH"
	case SevCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

func CompareSnapshots(old, current *Snapshot, pinned map[string]string, trustOnFirstUse bool) []DriftFinding {
	if old == nil {
		return firstScanFindings(current, pinned, trustOnFirstUse)
	}
	return sessionFindings(old, current, pinned)
}

func firstScanFindings(current *Snapshot, pinned map[string]string, trustOnFirstUse bool) []DriftFinding {
	var findings []DriftFinding
	if trustOnFirstUse {
		findings = append(findings, DriftFinding{
			Server:    current.Server,
			DriftType: DriftFirstScan,
			Severity:  SevPass,
			Finding:   fmt.Sprintf("first scan for server %q — baseline established", current.Server),
		})
	}
	if len(pinned) > 0 {
		curMap := toolMap(current)
		findings = append(findings, checkPinned(curMap, current.Server, pinned)...)
	}
	return findings
}

func sessionFindings(old, current *Snapshot, pinned map[string]string) []DriftFinding {
	oldMap := toolMap(old)
	curMap := toolMap(current)

	var findings []DriftFinding

	for name := range curMap {
		if _, ok := oldMap[name]; !ok {
			findings = append(findings, DriftFinding{
				Server:    current.Server,
				Tool:      name,
				DriftType: DriftToolAdded,
				Severity:  SevMedium,
				Finding:   fmt.Sprintf("new tool %q added since last scan", name),
			})
		}
	}

	for name := range oldMap {
		if _, ok := curMap[name]; !ok {
			findings = append(findings, DriftFinding{
				Server:    current.Server,
				Tool:      name,
				DriftType: DriftToolRemoved,
				Severity:  SevInfo,
				Finding:   fmt.Sprintf("tool %q removed since last scan", name),
			})
		}
	}

	for name, cur := range curMap {
		oldEntry, ok := oldMap[name]
		if !ok {
			continue
		}
		findings = append(findings, compareToolEntry(oldEntry, cur, current.Server)...)
	}

	findings = append(findings, checkPinned(curMap, current.Server, pinned)...)

	if len(findings) == 0 {
		since := old.ScannedAt.Format(time.RFC3339)
		if old.ScannedAt.IsZero() {
			since = "(unknown)"
		}
		findings = append(findings, DriftFinding{
			Server:   current.Server,
			Severity: SevPass,
			Finding:  fmt.Sprintf("no tool drift detected since %s", since),
		})
	}

	return findings
}

func toolMap(s *Snapshot) map[string]ToolEntry {
	m := make(map[string]ToolEntry, len(s.Tools))
	for _, t := range s.Tools {
		m[t.Name] = t
	}
	return m
}

func compareToolEntry(old, cur ToolEntry, server string) []DriftFinding {
	var findings []DriftFinding

	if cur.DescriptionHash != old.DescriptionHash {
		findings = append(findings, DriftFinding{
			Server:    server,
			Tool:      cur.Name,
			DriftType: DriftDescriptionChanged,
			Severity:  SevMedium,
			Finding:   fmt.Sprintf("tool %q description changed since last scan", cur.Name),
			Detail:    fmt.Sprintf("old: %s, new: %s", old.DescriptionHash, cur.DescriptionHash),
		})
	}

	if cur.SchemaHash != old.SchemaHash {
		findings = append(findings, schemaChangeFinding(old, cur, server))
	}

	return findings
}

func schemaChangeFinding(old, cur ToolEntry, server string) DriftFinding {
	detail := fmt.Sprintf("old: %s, new: %s", old.SchemaHash, cur.SchemaHash)
	sev := SevHigh
	finding := fmt.Sprintf("tool %q schema changed since last scan", cur.Name)

	added := setDifference(cur.Properties, old.Properties)
	removed := setDifference(old.Properties, cur.Properties)
	if len(added) > 0 && len(removed) == 0 {
		finding = fmt.Sprintf("tool %q schema broadened: new properties %v", cur.Name, added)
	} else if len(removed) > 0 && len(added) == 0 {
		sev = SevInfo
		finding = fmt.Sprintf("tool %q schema narrowed: removed properties %v", cur.Name, removed)
	}

	return DriftFinding{
		Server:    server,
		Tool:      cur.Name,
		DriftType: DriftSchemaChanged,
		Severity:  sev,
		Finding:   finding,
		Detail:    detail,
	}
}

func checkPinned(curMap map[string]ToolEntry, server string, pinned map[string]string) []DriftFinding {
	var findings []DriftFinding
	for pinnedKey, expectedHash := range pinned {
		cur, ok := curMap[pinnedKey]
		if !ok {
			findings = append(findings, DriftFinding{
				Server:    server,
				Tool:      pinnedKey,
				DriftType: DriftPinnedMissing,
				Severity:  SevHigh,
				Finding:   fmt.Sprintf("pinned tool %q not found on server", pinnedKey),
			})
			continue
		}
		actualHash := cur.DescriptionHash
		if actualHash != expectedHash {
			findings = append(findings, DriftFinding{
				Server:    server,
				Tool:      pinnedKey,
				DriftType: DriftPinnedMismatch,
				Severity:  SevCritical,
				Finding: fmt.Sprintf("pinned tool %q hash mismatch: expected %s, got %s",
					pinnedKey, expectedHash, actualHash),
			})
		}
	}
	return findings
}

func setDifference(a, b []string) []string {
	bSet := set.From[string](b)
	var diff []string
	for _, v := range a {
		if !bSet.Contains(v) {
			diff = append(diff, v)
		}
	}
	return diff
}
