package intel

import (
	"slices"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	tf, err := LoadDefaults()
	if err != nil {
		t.Fatalf("unexpected error loading defaults: %v", err)
	}
	if tf.Version == "" {
		t.Error("expected non-empty version")
	}
	if tf.GeneratedAt == "" {
		t.Error("expected non-empty generated_at")
	}
	if len(tf.Trusted) == 0 {
		t.Error("expected non-empty trusted list")
	}

	found := slices.Contains(tf.Trusted, "@anthropic/")
	if !found {
		t.Error("expected @anthropic/ in trusted list")
	}
}

func TestDefaultTrustAge(t *testing.T) {
	tf, err := LoadDefaults()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	age := tf.Age()
	if age < 0 {
		age = -age
	}
	if age > 365*24*60*60*1000*1000*1000 { // nanoseconds in 365 days
		t.Errorf("expected age under 365 days, got %v", age)
	}
}

func TestDefaultTrustStaleness(t *testing.T) {
	tf, err := LoadDefaults()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tf.IsStale(20 * 365 * 24 * 60 * 60 * 1000 * 1000 * 1000) {
		t.Error("fresh embedded config should not be stale with 20 year max")
	}
}

func TestDefaultTrustKnownSafeScopes(t *testing.T) {
	tf, err := LoadDefaults()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := map[string]bool{
		"@anthropic/":            true,
		"@modelcontextprotocol/": true,
		"@microsoft/":            true,
		"@google/":               true,
		"@vercel/":               true,
		"@cloudflare/":           true,
	}

	for _, trusted := range tf.Trusted {
		if expected[trusted] {
			delete(expected, trusted)
		}
	}

	if len(expected) > 0 {
		for missing := range expected {
			t.Errorf("expected %s in trusted list", missing)
		}
	}
}
