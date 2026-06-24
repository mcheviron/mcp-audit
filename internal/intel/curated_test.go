package intel

import (
	"slices"
	"testing"

	"github.com/hashicorp/go-set"
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

	expected := set.From[string]([]string{
		"@anthropic/",
		"@modelcontextprotocol/",
		"@microsoft/",
		"@google/",
		"@vercel/",
		"@cloudflare/",
	})

	for _, trusted := range tf.Trusted {
		if expected.Contains(trusted) {
			expected.Remove(trusted)
		}
	}

	if expected.Size() > 0 {
		for _, missing := range expected.Slice() {
			t.Errorf("expected %s in trusted list", missing)
		}
	}
}
