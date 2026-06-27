package scanner

import "strings"

func classifyPurpose(toolName, toolDesc string) float64 {
	combined := strings.ToLower(toolName + " " + toolDesc)
	for _, v := range mutatingVerbs {
		if strings.Contains(combined, v) {
			return 1.0
		}
	}
	for _, v := range retrievalVerbs {
		if strings.Contains(combined, v) {
			return 0.4
		}
	}
	return 0.7
}

func echoFactor(match, probeText string) float64 {
	if probeText == "" || match == "" {
		return 1.0
	}
	probeLower := strings.ToLower(probeText)
	matchLower := strings.ToLower(match)
	if len(matchLower) < 5 {
		return 1.0
	}
	window := min(len(matchLower), 8)
	for i := 0; i+window <= len(matchLower); i++ {
		substr := matchLower[i : i+window]
		if strings.Contains(probeLower, substr) {
			return 0.2
		}
	}
	return 1.0
}
