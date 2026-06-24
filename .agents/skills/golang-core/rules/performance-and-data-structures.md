---
title: Performance And Data Structures
---

# Performance And Data Structures

## Purpose

Guide low-risk performance improvements with measurable impact.

## When To Apply

Use for hot paths, allocation-heavy flows, large collections, and performance-sensitive refactors.

## Mandatory Rules

- Measure or profile before optimizing.
- Favor simple algorithmic improvements before micro-optimizations.
- Preallocate slices/maps when size is known or bounded.
- Use `strings.Builder` for repeated string concatenation in loops.
- Avoid unnecessary `string` and `[]byte` conversions.
- Choose data structures based on access patterns, not habit.
- For set-like behavior, prefer `go-set` where it improves clarity and correctness.
- Keep optimizations readable and reversible.

## Examples

```go
out := make([]Result, 0, len(items))
for _, item := range items {
	out = append(out, transform(item))
}
```

```go
var b strings.Builder
for _, part := range parts {
	b.WriteString(part)
}
return b.String()
```
