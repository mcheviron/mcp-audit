package scanner

import (
	"math"
	"testing"
)

func TestShannonCharEntropyEmpty(t *testing.T) {
	if s := shannonCharEntropy(""); s != 0 {
		t.Errorf("empty string entropy should be 0, got %.2f", s)
	}
}

func TestScoreDescriptionQualityEmpty(t *testing.T) {
	if s := scoreDescriptionQuality(""); s != 0 {
		t.Errorf("empty description score should be 0, got %.2f", s)
	}
}

func TestScoreDescriptionQualityWhitespace(t *testing.T) {
	if s := scoreDescriptionQuality("   "); s != 0 {
		t.Errorf("whitespace description score should be 0, got %.2f", s)
	}
}

func TestScoreDescriptionQualityShort(t *testing.T) {
	s := scoreDescriptionQuality("ab")
	if s > 50 {
		t.Errorf("short (2 char) description should score <= 50, got %.2f", s)
	}
}

func TestScoreDescriptionQualityMedium(t *testing.T) {
	s := scoreDescriptionQuality("this is a thirty character desc")
	if s < 50 {
		t.Errorf("30-char description should score >= 50, got %.2f", s)
	}
}

func TestScoreDescriptionQualityLong(t *testing.T) {
	desc := "This is a natural language description that should be long enough to get a high score for both length and entropy"
	s := scoreDescriptionQuality(desc)
	if s < 90 {
		t.Errorf("long natural description should score >= 90, got %.2f", s)
	}
}

func TestAggregateRiskPerfect(t *testing.T) {
	factors := RiskFactors{
		TyposquatDistance:  100,
		CVECount:           100,
		CapabilityBreadth:  100,
		DescriptionQuality: 100,
		NetworkExposure:    100,
	}
	score := AggregateRisk(factors, DefaultWeights())
	if score != 100 {
		t.Errorf("perfect factors should score 100, got %.2f", score)
	}
}

func TestAggregateRiskHighRisk(t *testing.T) {
	factors := RiskFactors{
		TyposquatDistance:  20,
		CVECount:           10,
		CapabilityBreadth:  30,
		DescriptionQuality: 0,
		NetworkExposure:    30,
	}
	score := AggregateRisk(factors, DefaultWeights())
	if score > 30 {
		t.Errorf("high-risk server should score <= 30, got %.2f", score)
	}
}

func TestAggregateRiskClamped(t *testing.T) {
	factors := RiskFactors{
		TyposquatDistance:  200,
		CVECount:           200,
		CapabilityBreadth:  200,
		DescriptionQuality: 200,
		NetworkExposure:    200,
	}
	score := AggregateRisk(factors, DefaultWeights())
	if score != 100 {
		t.Errorf("clamped score should be 100, got %.2f", score)
	}
}

func TestDefaultWeightsSumToOne(t *testing.T) {
	w := DefaultWeights()
	sum := w.Typosquat + w.CVE + w.Capability + w.Description + w.Network
	if math.Abs(sum-1.0) > 0.001 {
		t.Errorf("default weights should sum to 1.0, got %.3f", sum)
	}
}

func TestParseWeightsValid(t *testing.T) {
	w, err := ParseWeights("0.30,0.25,0.20,0.15,0.10")
	if err != nil {
		t.Fatalf("valid weights should not error: %v", err)
	}
	if w.Typosquat != 0.30 {
		t.Errorf("typosquat weight should be 0.30, got %f", w.Typosquat)
	}
	if w.Network != 0.10 {
		t.Errorf("network weight should be 0.10, got %f", w.Network)
	}
}

func TestParseWeightsEmpty(t *testing.T) {
	w, err := ParseWeights("")
	if err != nil {
		t.Fatalf("empty weights should not error: %v", err)
	}
	sum := w.Typosquat + w.CVE + w.Capability + w.Description + w.Network
	if math.Abs(sum-1.0) > 0.001 {
		t.Errorf("default weights should sum to 1.0, got %.3f", sum)
	}
}

func TestParseWeightsBadCount(t *testing.T) {
	_, err := ParseWeights("0.25,0.30")
	if err == nil {
		t.Error("wrong count should error")
	}
}

func TestParseWeightsNoSumTo1(t *testing.T) {
	_, err := ParseWeights("0.25,0.25,0.25,0.25,0.25")
	if err == nil {
		t.Error("sum != 1.0 should error")
	}
}

func TestParseWeightsNegative(t *testing.T) {
	_, err := ParseWeights("-0.1,0.5,0.3,0.2,0.1")
	if err == nil {
		t.Error("negative weight should error")
	}
}

func TestParseWeightsOver1(t *testing.T) {
	_, err := ParseWeights("1.5,0,0,0,0")
	if err == nil {
		t.Error("weight > 1 should error")
	}
}
