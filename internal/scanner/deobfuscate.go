package scanner

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"unicode/utf8"
)

//go:embed confusables.json
var confusablesData string

var confusableMap map[string]string

func init() {
	confusableMap = loadConfusables(confusablesData)
}

func loadConfusables(data string) map[string]string {
	m := map[string]string{}
	if err := json.Unmarshal([]byte(data), &m); err != nil {
		slog.Warn("load confusables", "err", err)
		m = map[string]string{}
	}
	return m
}

type deobStage func(desc string) (string, []Result, bool)

func isBidiRune(r rune) bool {
	switch r {
	case 0x202E, 0x202D, 0x202A, 0x202B, 0x202C,
		0x2066, 0x2067, 0x2068, 0x2069:
		return true
	}
	return false
}

func isZeroWidthRune(r rune) bool {
	switch r {
	case 0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060, 0x200E, 0x200F:
		return true
	}
	return false
}

func containsBidiRune(s string) bool {
	for _, r := range s {
		if isBidiRune(r) {
			return true
		}
	}
	return false
}

func countZeroWidthRunes(s string) int {
	n := 0
	for _, r := range s {
		if isZeroWidthRune(r) {
			n++
		}
	}
	return n
}

var b64Pattern = regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)

func stripUnicodeTags(desc string) (string, []Result, bool) {
	var findings []Result
	tagCount := 0
	for _, r := range desc {
		if r >= 0xE0001 && r <= 0xE007F {
			tagCount++
		}
	}
	if tagCount > 0 {
		filtered := strings.Map(func(r rune) rune {
			if r >= 0xE0001 && r <= 0xE007F {
				return -1
			}
			return r
		}, desc)
		findings = append(findings, Result{
			Severity: SevMedium,
			Type:     "static",
			Finding:  fmt.Sprintf("description contains %d hidden Unicode tag characters", tagCount),
		})
		return filtered, findings, true
	}
	return desc, nil, false
}

func detectBiDi(desc string) (string, []Result, bool) {
	var findings []Result
	if containsBidiRune(desc) {
		findings = append(findings, Result{
			Severity: SevHigh,
			Type:     "static",
			Finding:  "description contains bidirectional text override characters",
		})
	}
	return desc, findings, false
}

func scanZeroWidth(desc string) (string, []Result, bool) {
	n := countZeroWidthRunes(desc)
	if n >= 5 {
		return desc, []Result{{
			Severity: SevLow,
			Type:     "static",
			Finding:  fmt.Sprintf("description contains %d zero-width characters", n),
		}}, false
	}
	return desc, nil, false
}

func decodeBase64(desc string) (string, []Result, bool) {
	var findings []Result
	matches := b64Pattern.FindAllString(desc, -1)
	for _, match := range matches {
		decoded, err := base64.StdEncoding.DecodeString(match)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(match)
			if err != nil {
				continue
			}
		}
		if len(decoded) < 20 {
			findings = append(findings, Result{
				Severity: SevInfo,
				Type:     "static",
				Finding:  "description contains short Base64-encoded content",
			})
			continue
		}
		decodedStr := string(decoded)
		if !utf8.Valid(decoded) {
			continue
		}
		for _, p := range PromptInjectionPatterns {
			if m := p.FindString(decodedStr); m != "" {
				findings = append(findings, Result{
					Severity: SevHigh,
					Type:     "static",
					Finding:  fmt.Sprintf("description contains Base64-encoded injection payload: %q", m),
					Detail:   redactDetail(decodedStr),
				})
				return desc, findings, false
			}
		}
		findings = append(findings, Result{
			Severity: SevInfo,
			Type:     "static",
			Finding:  fmt.Sprintf("description contains Base64-encoded content (decoded: %q)", redactDetail(decodedStr)),
		})
	}
	return desc, findings, false
}

func detectConfusables(desc string) (string, []Result, bool) {
	var findings []Result
	var confusableParts []string
	for _, r := range desc {
		hex := fmt.Sprintf("%04X", r)
		if ascii, ok := confusableMap[hex]; ok {
			confusableParts = append(confusableParts, ascii)
		}
	}
	if len(confusableParts) > 0 {
		asciiText := strings.Join(confusableParts, "")
		findings = append(findings, Result{
			Severity: SevMedium,
			Type:     "static",
			Finding:  fmt.Sprintf("description contains confusable characters interpreting as %q", asciiText),
		})
	}
	return desc, findings, false
}

var deobStages = []deobStage{
	stripUnicodeTags,
	detectBiDi,
	scanZeroWidth,
	decodeBase64,
	detectConfusables,
}

func deobfuscate(desc string) (string, []Result) {
	var allFindings []Result
	current := desc
	for _, stage := range deobStages {
		next, findings, stop := stage(current)
		allFindings = append(allFindings, findings...)
		if current != next {
			current = next
		}
		if stop {
			break
		}
	}
	return current, allFindings
}
