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

## Nil Slices

- Prefer nil initialization for local slice variables (`var t []string`) over empty composite literals (`t := []string{}`).
- Do not create APIs that force callers to distinguish between nil and empty slices; both should behave identically.
- Use `len(s) == 0` to check for emptiness, not `s == nil`.

```go
// Good: nil slice, ready to append.
var results []Result
for _, item := range items {
	results = append(results, transform(item))
}
```

```go
// Avoid: unnecessary empty composite literal.
results := []Result{}
for _, item := range items {
	results = append(results, transform(item))
}
```

## Copy Safety

- Do not copy a value of type `T` if its methods are associated with the pointer type `*T` (e.g., types with `sync.Mutex` fields).
- Do not copy structs from other packages that contain synchronization primitives (`sync.Mutex`, `sync.WaitGroup`, `sync.Once`).
- Author APIs to take and return pointer types when structs contain fields that should not be copied.

```go
// Avoid: copying a struct with a mutex.
type Scanner struct {
	mu      sync.Mutex
	results []Result
}

s := Scanner{}
s2 := s // copies the mutex — data race risk
```

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
