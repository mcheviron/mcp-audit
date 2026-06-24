package scanner

import (
	_ "embed"
	"encoding/json"
	"fmt"
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
			continue
		}
		mappings[f.name] = fm
	}
}

type Control struct {
	Framework string
	Control   string
}

func MapToCompliance(findingType string, severity Severity) []Control {
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

func normalizeFindingType(t string) string {
	t = strings.ToLower(t)
	switch {
	case strings.Contains(t, "credential"):
		return "credential_leak"
	case strings.Contains(t, "secret"):
		return "secret_leak"
	case strings.Contains(t, "injection") || strings.Contains(t, "prompt"):
		return "prompt_injection"
	case strings.Contains(t, "ssrf") ||
		(strings.Contains(t, "dynamic") &&
			(strings.Contains(t, "internal") || strings.Contains(t, "redirect"))):
		return "ssrf"
	case strings.Contains(t, "tool") || strings.Contains(t, "capability") || strings.Contains(t, "analysis"):
		return "tool_capability"
	case strings.Contains(t, "shadow"):
		return "shadowing"
	case strings.Contains(t, "typosquat") || strings.Contains(t, "distance"):
		return "typosquat"
	case strings.Contains(t, "cve"):
		return "cve"
	case strings.Contains(t, "config") || strings.Contains(t, "misconfig") || strings.Contains(t, "parse"):
		return "config_misconfig"
	default:
		return t
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
