package scanner

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/hashicorp/go-set"
)

//go:embed compliance/soc2.json
var soc2Data []byte

//go:embed compliance/nist-ai-rmf.json
var nistAIRMFData []byte

//go:embed compliance/owasp-llm.json
var owaspLLMData []byte

//go:embed compliance/mitre-atlas.json
var mitreATLASData []byte

//go:embed compliance/eu-ai-act.json
var euAIActData []byte

type frameworkMapping struct {
	Framework    string              `json:"framework"`
	ShortName    string              `json:"short_name"`
	Version      string              `json:"version"`
	FindingTypes map[string][]string `json:"finding_types"`
}

var mappings map[string]frameworkMapping

func LoadMappings() {
	mappings = make(map[string]frameworkMapping)
	files := []struct {
		name string
		data []byte
	}{
		{"soc2", soc2Data},
		{"nist-ai-rmf", nistAIRMFData},
		{"owasp-llm", owaspLLMData},
		{"mitre-atlas", mitreATLASData},
		{"eu-ai-act", euAIActData},
	}
	for _, f := range files {
		var fm frameworkMapping
		if err := json.Unmarshal(f.data, &fm); err != nil {
			slog.Warn("load compliance mapping", "framework", f.name, "err", err)
			continue
		}
		mappings[f.name] = fm
	}
}

type Control struct {
	Framework string
	Control   string
}

func MapToCompliance(findingType FindingType, severity Severity) []Control {
	if mappings == nil {
		LoadMappings()
	}
	var controls []Control
	normalizedType := normalizeFindingType(findingType)
	for _, fm := range mappings {
		if ctrls, ok := fm.FindingTypes[normalizedType]; ok {
			for _, ctrl := range ctrls {
				controls = append(controls, Control{
					Framework: fm.Framework,
					Control:   ctrl,
				})
			}
		}
	}
	return controls
}

func normalizeFindingType(t FindingType) string {
	s := strings.ToLower(string(t))
	switch {
	case strings.Contains(s, "credential"):
		return "credential_leak"
	case strings.Contains(s, "secret"):
		return "secret_leak"
	case strings.Contains(s, "injection") || strings.Contains(s, "prompt"):
		return "prompt_injection"
	case strings.Contains(s, "ssrf") ||
		(strings.Contains(s, "dynamic") &&
			(strings.Contains(s, "internal") || strings.Contains(s, "redirect"))):
		return "ssrf"
	case strings.Contains(s, "tool") || strings.Contains(s, "capability") || strings.Contains(s, "analysis"):
		return "tool_capability"
	case strings.Contains(s, "shadow"):
		return "shadowing"
	case strings.Contains(s, "typosquat") || strings.Contains(s, "distance"):
		return "typosquat"
	case strings.Contains(s, "cve"):
		return "cve"
	case strings.Contains(s, "config") || strings.Contains(s, "misconfig") || strings.Contains(s, "parse"):
		return "config_misconfig"
	default:
		return string(t)
	}
}

func MapResultsToCompliance(results []Result) []Result {
	if mappings == nil {
		LoadMappings()
	}
	for i := range results {
		tagMap := set.New[string](0)
		var tags []ComplianceTag
		for _, ctrl := range MapToCompliance(results[i].Type, results[i].Severity) {
			key := fmt.Sprintf("%s/%s", ctrl.Framework, ctrl.Control)
			if !tagMap.Contains(key) {
				tagMap.Insert(key)
				tags = append(tags, ComplianceTag(ctrl))
			}
		}
		results[i].Compliance = tags
	}
	return results
}

func GetAllFrameworkShortNames() []string {
	if mappings == nil {
		LoadMappings()
	}
	names := make([]string, 0, len(mappings))
	for _, fm := range mappings {
		names = append(names, fm.ShortName)
	}
	return names
}
