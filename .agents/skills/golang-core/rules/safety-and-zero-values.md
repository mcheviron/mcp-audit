---
title: Safety And Zero Values
---

# Safety And Zero Values

## Purpose

Prevent common Go correctness bugs before they ship.

## When To Apply

Use for pointer-heavy code, collection handling, type assertions, resource management, and boundary code.

## Mandatory Rules

- Avoid nil-interface traps: interface values can be non-nil while holding a nil pointer.
- Initialize maps before writes.
- Copy inbound slices/maps before storing when mutation by caller is possible.
- Use comma-ok checks for type assertions and map lookups where absence is valid.
- Close resources on all paths; keep cleanup close to acquisition.
- Avoid large-loop `defer` patterns that postpone cleanup for too long.
- Validate bounds before integer narrowing or signed/unsigned conversions.
- Favor designs where useful zero values are safe defaults.

## Examples

```go
func CloneIDs(ids []string) []string {
	out := make([]string, len(ids))
	copy(out, ids)
	return out
}
```

```go
// Avoid writing to a nil map.
var counters map[string]int
counters["ok"]++
```

```go
// Prefer explicit map initialization before mutation.
counters := make(map[string]int)
counters["ok"]++
```
