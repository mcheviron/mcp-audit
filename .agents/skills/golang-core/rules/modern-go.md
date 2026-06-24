---
title: Modern Go
---

# Modern Go

## Purpose

Prefer current, clear Go patterns over legacy or workaround-heavy code.

## When To Apply

Use when introducing new code or modernizing existing implementations.

## Mandatory Rules

- Prefer generics when they improve type safety and clarity over loose typing.
- Be wary of premature generic use; start with concrete types when only one type is used in practice. Conventional approaches often work without added complexity.
- Do not use generics to invent domain-specific languages or error-handling frameworks. Write code, don't design types.
- If generics are used in exported APIs, document them and include motivating runnable examples.
- Prefer `any` over `interface{}` in modern code.
- Use standard library helpers (`slices`, `maps`, `cmp`) when they improve readability.
- Use `errors.Join` for combining independent errors.
- Prefer `errors.AsType[T]` (Go 1.26+) over `errors.As` for concrete type matching.
- Apply the Go 1.26 pointer rule: `new(Type)` for zero values, `new(expr)` for expression pointers.
- Keep context usage modern and explicit (timeout/cancellation propagation).
- Replace outdated patterns only when the replacement improves clarity or correctness.

## Examples

```go
func MapSlice[T any, R any](in []T, fn func(T) R) []R {
	out := make([]R, 0, len(in))
	for _, v := range in {
		out = append(out, fn(v))
	}
	return out
}
```

```go
// Go 1.26 pointer allocation
var countPtr *int = new(int)      // zero value: *countPtr == 0
limitPtr := new(int64(300))       // expression: *limitPtr == 300
```

```go
// Prefer errors.AsType over errors.As for concrete types
if ee, ok := errors.AsType[*exitError](err); ok {
	os.Exit(ee.code)
}
```
