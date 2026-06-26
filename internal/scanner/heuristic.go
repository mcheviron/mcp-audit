package scanner

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/hashicorp/go-set"
	"github.com/mcheviron/mcp-audit/internal/mcp"
)

type RiskFactors struct {
	TyposquatDistance  float64
	CVECount           float64
	CapabilityBreadth  float64
	DescriptionQuality float64
	NetworkExposure    float64
}

type Weights struct {
	Typosquat   float64
	CVE         float64
	Capability  float64
	Description float64
	Network     float64
}

func DefaultWeights() Weights {
	return Weights{
		Typosquat:   0.25,
		CVE:         0.30,
		Capability:  0.20,
		Description: 0.15,
		Network:     0.10,
	}
}

func ParseWeights(s string) (Weights, error) {
	w := DefaultWeights()
	if s == "" {
		return w, nil
	}
	parts := strings.Split(s, ",")
	if len(parts) != 5 {
		return w, fmt.Errorf("score-weights: need 5 comma-separated floats (typosquat,cve,capability,description,network)")
	}
	vals := make([]float64, 5)
	for i, p := range parts {
		p = strings.TrimSpace(p)
		var v float64
		if _, err := fmt.Sscanf(p, "%f", &v); err != nil {
			return w, fmt.Errorf("invalid weight at position %d: %q", i+1, p)
		}
		if v < 0 || v > 1 {
			return w, fmt.Errorf("weight at position %d must be between 0 and 1, got %f", i+1, v)
		}
		vals[i] = v
	}
	sum := vals[0] + vals[1] + vals[2] + vals[3] + vals[4]
	if math.Abs(sum-1.0) > 0.001 {
		return w, fmt.Errorf("weights must sum to 1.0, got %f", sum)
	}
	w.Typosquat = vals[0]
	w.CVE = vals[1]
	w.Capability = vals[2]
	w.Description = vals[3]
	w.Network = vals[4]
	return w, nil
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}

func AggregateRisk(factors RiskFactors, weights Weights) float64 {
	score := factors.TyposquatDistance*weights.Typosquat +
		factors.CVECount*weights.CVE +
		factors.CapabilityBreadth*weights.Capability +
		factors.DescriptionQuality*weights.Description +
		factors.NetworkExposure*weights.Network
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return round2(score)
}

func shannonCharEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var freq [128]int
	distinct := 0
	asciiLen := 0
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 128 {
			asciiLen++
			if freq[b] == 0 {
				distinct++
			}
			freq[b]++
		}
	}
	if distinct <= 1 || asciiLen == 0 {
		return 0
	}
	var entropy float64
	length := float64(asciiLen)
	normFactor := math.Log2(float64(distinct))
	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	normalized := (entropy / normFactor) * 100
	if normalized > 100 {
		normalized = 100
	}
	return normalized
}

func scoreDescriptionQuality(desc string) float64 {
	trimmed := strings.TrimSpace(desc)
	if trimmed == "" {
		return 0
	}
	length := len(trimmed)
	var lengthScore float64
	switch {
	case length <= 20:
		lengthScore = 0
	case length < 50:
		lengthScore = 50
	default:
		lengthScore = 100
	}
	entropyScore := shannonCharEntropy(trimmed)
	return round2((lengthScore + entropyScore) / 2)
}

func ComputeServerScores(results []Result, allTools map[string][]mcp.Tool, weights Weights) []Result {
	serverFactors := extractRiskFactors(results, allTools)
	enriched := make([]Result, len(results))
	for i, r := range results {
		enriched[i] = r
		if factors, ok := serverFactors[r.Server]; ok {
			enriched[i].Factors = factors
			enriched[i].Score = AggregateRisk(factors, weights)
		}
	}
	return enriched
}

type resultCounts struct {
	typosquatCount   int
	minTyposquatDist int
	cveCount         int
	cveHighCount     int
	hasShell         bool
	capCount         int
	highSevNetwork   bool
}

func computeTyposquatFactor(rc resultCounts) float64 {
	if rc.typosquatCount == 0 {
		return 100
	}
	switch {
	case rc.minTyposquatDist <= 1:
		return 10
	case rc.minTyposquatDist == 2:
		return 40
	default:
		return 70
	}
}

func computeCVEFactor(rc resultCounts) float64 {
	if rc.cveCount == 0 {
		return 100
	}
	switch {
	case rc.cveHighCount > 2:
		return 10
	case rc.cveHighCount > 0:
		return 30
	case rc.cveCount > 3:
		return 50
	default:
		return 70
	}
}

func computeCapabilityFactor(rc resultCounts) float64 {
	switch {
	case rc.hasShell:
		return 20
	case rc.capCount > 2:
		return 50
	case rc.capCount > 0:
		return 75
	default:
		return 100
	}
}

func computeNetworkFactor(rc resultCounts) float64 {
	if rc.highSevNetwork {
		return 10
	}
	return 100
}

func extractRiskFactors(results []Result, allTools map[string][]mcp.Tool) map[string]RiskFactors {
	factors := map[string]RiskFactors{}

	counts := map[string]*resultCounts{}
	servers := set.New[string](0)
	for _, r := range results {
		s := r.Server
		if !servers.Contains(s) {
			servers.Insert(s)
			counts[s] = &resultCounts{minTyposquatDist: 100}
		}
		rc := counts[s]
		switch r.Type {
		case "static":
			if r.Severity == SevInfo && containsPattern(r.Finding, "typosquat", "distance") {
				rc.typosquatCount++
				if d := extractDistance(r.Finding); d > 0 && d < rc.minTyposquatDist {
					rc.minTyposquatDist = d
				}
			}
			if containsPattern(r.Finding, "shell") {
				rc.hasShell = true
			}
			if containsPattern(r.Finding, "capabilities:") {
				rc.capCount++
			}
		case "cve":
			rc.cveCount++
			if r.Severity >= SevHigh {
				rc.cveHighCount++
			}
		case "dynamic":
			if r.Severity >= SevHigh && containsPattern(r.Finding,
				"redirect", "internal", "metadata", "leaked", "exposed") {
				rc.highSevNetwork = true
			}
		}
	}

	for server, rc := range counts {
		rf := RiskFactors{
			TyposquatDistance:  computeTyposquatFactor(*rc),
			CVECount:           computeCVEFactor(*rc),
			CapabilityBreadth:  computeCapabilityFactor(*rc),
			DescriptionQuality: 100,
			NetworkExposure:    computeNetworkFactor(*rc),
		}

		if tools, ok := allTools[server]; ok {
			var descQualityTotal float64
			var descCount int
			for _, tool := range tools {
				descQualityTotal += scoreDescriptionQuality(tool.Description)
				descCount++
			}
			if descCount > 0 {
				rf.DescriptionQuality = descQualityTotal / float64(descCount)
			}
		}

		factors[server] = rf
	}

	return factors
}

func containsPattern(s string, patterns ...string) bool {
	lower := strings.ToLower(s)
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

var distanceDigitsRE = regexp.MustCompile(`distance\s+(\d+)`)

func extractDistance(finding string) int {
	idx := strings.Index(strings.ToLower(finding), "distance")
	if idx < 0 {
		return 0
	}
	match := distanceDigitsRE.FindStringSubmatch(finding[idx:])
	if len(match) < 2 {
		return 0
	}
	digits, _ := strconv.Atoi(match[1])
	return digits
}
