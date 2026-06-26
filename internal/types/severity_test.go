package types

import (
	"encoding/json"
	"testing"
)

func TestSeverityRoundTrip(t *testing.T) {
	for _, s := range []Severity{SevPass, SevInfo, SevLow, SevMedium, SevHigh, SevCritical} {
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var got Severity
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got != s {
			t.Fatalf("round-trip: got %v want %v", got, s)
		}
	}
}

func TestSeverityJSONIsString(t *testing.T) {
	b, _ := json.Marshal(SevHigh)
	if string(b) != `"HIGH"` {
		t.Fatalf("expected \"HIGH\", got %s", string(b))
	}
}
