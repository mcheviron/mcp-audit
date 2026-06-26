package scanner

import (
	"fmt"
	"math"
	"strings"
	"time"
)

type probeTiming struct {
	server     string
	duration   time.Duration
	configPath string
}

var keywordWeights = map[string]float64{
	"access_key": 1.0,
	"token":      0.9,
	"password":   0.9,
	"secret":     0.8,
	"credential": 0.8,
	"private":    0.8,
	"admin":      0.6,
	"config":     0.6,
	"internal":   0.6,
}

func scoreResponse(body string) float64 {
	if len(body) == 0 {
		return 0
	}
	lower := strings.ToLower(body)
	var totalWeight float64
	for i := 0; i < len(lower); i++ {
		for keyword, weight := range keywordWeights {
			if i+len(keyword) <= len(lower) && lower[i:i+len(keyword)] == keyword {
				totalWeight += weight
			}
		}
	}
	normFactor := float64(len(body)) / 100.0
	if normFactor < 1 {
		normFactor = 1
	}
	score := totalWeight / normFactor
	if score > 1.0 {
		score = 1.0
	}
	return score
}

func shannonEntropy(body string) float64 {
	if len(body) == 0 {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(body); i++ {
		freq[body[i]]++
	}
	var entropy float64
	length := float64(len(body))
	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func entropyBand(entropy float64) string {
	switch {
	case entropy > 7.5:
		return "encrypted"
	case entropy >= 3.0:
		return "text"
	case entropy >= 1.5:
		return "structured"
	default:
		return "suspicious"
	}
}

type ResponseClass int

const (
	ResponseMetadata ResponseClass = iota
	ResponseError
	ResponseData
	ResponseBinary
)

func (rc ResponseClass) String() string {
	switch rc {
	case ResponseMetadata:
		return "metadata"
	case ResponseError:
		return "error"
	case ResponseData:
		return "data"
	case ResponseBinary:
		return "binary"
	default:
		return "unknown"
	}
}

func classifyResponse(body, contentType string) ResponseClass {
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "octet-stream") || strings.Contains(ct, "image") ||
		strings.Contains(ct, "audio") || strings.Contains(ct, "video") ||
		strings.Contains(ct, "pdf") {
		return ResponseBinary
	}
	if strings.Contains(ct, "json") || strings.Contains(ct, "xml") || strings.Contains(ct, "text") {
		lowerBody := strings.ToLower(body)
		if strings.Contains(lowerBody, `"error"`) || strings.Contains(lowerBody, "exception") {
			return ResponseError
		}
		if MetadataPattern.MatchString(body) {
			return ResponseMetadata
		}
		return ResponseData
	}
	if isBinaryBody(body) {
		return ResponseBinary
	}
	return ResponseData
}

func isBinaryBody(body string) bool {
	if len(body) == 0 {
		return false
	}
	nonPrintable := 0
	for i := 0; i < len(body); i++ {
		b := body[i]
		if b < 0x20 && b != '\n' && b != '\r' && b != '\t' {
			nonPrintable++
		}
	}
	return float64(nonPrintable)/float64(len(body)) > 0.3
}

func analyzeTiming(timings []probeTiming) []Result {
	serverDurations := map[string][]time.Duration{}
	serverTimings := map[string][]probeTiming{}
	for _, t := range timings {
		serverDurations[t.server] = append(serverDurations[t.server], t.duration)
		serverTimings[t.server] = append(serverTimings[t.server], t)
	}

	var findings []Result
	for server, durations := range serverDurations {
		if len(durations) < 2 {
			continue
		}
		mean := meanDuration(durations)
		stddev := stddevDuration(durations, mean)
		if stddev == 0 {
			continue
		}
		threshold := mean - 2*stddev
		if threshold <= 0 {
			continue
		}
		for _, t := range serverTimings[server] {
			if t.duration < threshold {
				findings = append(findings, Result{
					Severity: SevInfo,
					Server:   server,
					Type:     "dynamic",
					Finding: fmt.Sprintf("anomalously fast response (%v vs mean %v) on %s — possible internal service access",
						t.duration, mean, server),
					ConfigPath: t.configPath,
				})
			}
		}
	}
	return findings
}

func meanDuration(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	var total time.Duration
	for _, d := range durations {
		total += d
	}
	return total / time.Duration(len(durations))
}

func stddevDuration(durations []time.Duration, mean time.Duration) time.Duration {
	if len(durations) < 2 {
		return 0
	}
	var sumSquares float64
	for _, d := range durations {
		diff := float64(d - mean)
		sumSquares += diff * diff
	}
	return time.Duration(math.Sqrt(sumSquares / float64(len(durations))))
}
