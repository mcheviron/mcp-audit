package types

import "strings"

type Severity int

const (
	SevPass Severity = iota
	SevInfo
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

type severityErr struct{}

var errSeverityParse = &severityErr{}

func (s Severity) String() string {
	switch s {
	case SevPass:
		return "PASS"
	case SevInfo:
		return "INFO"
	case SevLow:
		return "LOW"
	case SevMedium:
		return "MEDIUM"
	case SevHigh:
		return "HIGH"
	case SevCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

func (s Severity) StringLower() string {
	return strings.ToLower(s.String())
}

func ParseSeverity(s string) (Severity, bool) {
	switch strings.ToUpper(s) {
	case "PASS":
		return SevPass, true
	case "INFO":
		return SevInfo, true
	case "LOW":
		return SevLow, true
	case "MEDIUM":
		return SevMedium, true
	case "HIGH":
		return SevHigh, true
	case "CRITICAL":
		return SevCritical, true
	default:
		return SevPass, false
	}
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

func (s *Severity) UnmarshalJSON(data []byte) error {
	var raw string
	if err := jsonUnquote(data, &raw); err != nil {
		return err
	}
	v, ok := ParseSeverity(raw)
	if !ok {
		*s = SevPass
		return nil
	}
	*s = v
	return nil
}

func (*severityErr) Error() string { return "types: invalid severity payload" }

func jsonUnquote(data []byte, dst *string) error {
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return errSeverityParse
	}
	*dst = string(data[1 : len(data)-1])
	return nil
}
