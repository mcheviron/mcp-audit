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

## Keep Going

- Tests should generally not abort at the first encountered problem; prefer `t.Error` over `t.Fatal` so all failures are printed in a single run.
- Use `t.Fatal` when subsequent failures would be meaningless or misleading (e.g., setup failed, nil dereference inevitable).
- In table-driven tests without subtests: use `t.Error` + `continue` to report all failing cases.
- Inside subtests (`t.Run`): `t.Fatal` is acceptable since it ends only the current subtest, not the whole test.

```go
// Good: t.Error + continue in table tests without subtests.
func TestNormalize(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{" A ", "a"},
		{"", ""},
		{"  B  ", "b"},
	}
	for _, tc := range cases {
		got := Normalize(tc.in)
		if got != tc.want {
			t.Errorf("Normalize(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
```

## Failure Messages

- Include the name of the function that failed in the message.
- Include function inputs when short; otherwise name test cases with descriptive strings.
- Print the actual value before the expected value using `got` and `want` terminology.
- The conventional format is `FuncName(%v) = %v, want %v`.

```go
// Good: identifies function, input, got/want order.
got := Severity(s).String()
if got != want {
	t.Errorf("Severity(%d).String() = %q, want %q", s, got, want)
}
```

## Assertion Libraries

- Do not create assertion helper libraries that abstract away `t.Error`/`t.Fatal`.
- Prefer direct comparisons using the standard library (`cmp`, `fmt`).
- For domain-specific comparisons, return a value or error from a validation function rather than passing `*testing.T` to it.

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
