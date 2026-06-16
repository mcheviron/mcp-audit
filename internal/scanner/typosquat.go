package scanner

import (
	_ "embed"
	"strings"
)

//go:embed known_legitimate.txt
var legitimateDB string

//go:embed known_malicious.txt
var maliciousDB string

var knownLegitimate []string

var knownMalicious []string

func init() {
	knownLegitimate = parseList(legitimateDB)
	knownMalicious = parseList(maliciousDB)
}

func parseList(raw string) []string {
	lines := strings.Split(raw, "\n")
	var result []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			result = append(result, line)
		}
	}
	return result
}
