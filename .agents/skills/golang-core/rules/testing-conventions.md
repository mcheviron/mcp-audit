---
title: Testing Conventions
---

# Testing Conventions

## Purpose

Keep Go tests readable, diagnosable, and aligned with standard library testing patterns.

## When To Apply

Use when adding or reviewing unit tests, table tests, or test helpers.

## Mandatory Rules

- Prefer the standard `testing` package style; introduce assertion helpers only when they materially improve signal.
- Write failure messages so the reader can see what was tested and what differed.
- Prefer `got` and `want` naming in comparisons and failure output.
- Use table-driven tests when multiple cases share the same setup and assertion shape.
- Keep table cases readable; split oversized tables or extract focused helpers when the case matrix becomes hard to scan.
- Use subtests when they improve case isolation or reporting.
- Do not call `t.Fatal` or `t.FailNow` from spawned goroutines; report back to the main test goroutine instead.

## Examples

```go
func TestNormalize(t *testing.T) {
	got := Normalize(" A ")
	want := "a"
	if got != want {
		t.Fatalf("Normalize(%q) = %q, want %q", " A ", got, want)
	}
}
```

```go
func TestSeverityOrder(t *testing.T) {
	cases := []struct {
		name string
		in   Severity
		want string
	}{
		{"pass", SevPass, "PASS"},
		{"critical", SevCritical, "CRITICAL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.in.String()
			if got != tc.want {
				t.Fatalf("String() = %q, want %q", got, tc.want)
			}
		})
	}
}
```
