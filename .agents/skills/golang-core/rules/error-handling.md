---
title: Error Handling
---

# Error Handling

## Purpose

Make failures diagnosable without duplicating logs or leaking internal details.

## When To Apply

Use for any code path that returns, wraps, compares, aggregates, or logs errors.

## Mandatory Rules

- Define reusable sentinel errors with `errors.New` and keep them near the types they relate to.
- Wrap errors with `%w` and actionable context (`fmt.Errorf("load config: %w", err)`).
- Compare wrapped errors with `errors.Is` and prefer `errors.AsType[T]` for type matching in Go 1.26+.
- Use `errors.As` when you specifically need the target-setting form (e.g., interface types like `net.Error`).
- Keep error strings lowercase and without trailing punctuation.
- Log or return at a given layer, never both.
- Attach variable context (server names, URLs, tool names) via `fmt.Errorf` wrapping, not by logging at every layer.
- Prefer `errors.Join` when combining independent failures.
- Do not panic for expected operational errors.

## `%w` Placement

- Prefer placing `%w` at the end of an error string so text mirrors the error chain structure (newest annotation to oldest underlying error).
- Exception for sentinel errors: placing `%w` at the beginning can improve readability when the sentinel is the primary identifier.

```go
// Good: %w at the end.
return fmt.Errorf("probe %s: %w", url, err)

// Acceptable: %w at the beginning for sentinel errors.
return fmt.Errorf("%w: server unavailable", ErrServerDown)
```

## Panic Boundaries

- Panics are never allowed to escape across package boundaries; every exported function must recover or not panic.
- Panics are acceptable for API misuse (matching stdlib behavior, e.g., `regexp.MustCompile` panics on invalid input).
- Panics are acceptable as an internal implementation detail when there is a matching `recover` in the call chain.
- For invariant failures (unreachable internal state), prefer `log.Fatal` over `panic` — a panic in deferred functions can deadlock.
- Resist the temptation to recover panics to avoid crashes; doing so can propagate corrupted state. Use monitoring tools to surface unexpected failures instead.
- `Must` functions (`MustX`/`mustX`) that panic on failure are acceptable only during program startup, not for handling user input or runtime errors.

```go
// Good: panic for API misuse (matches stdlib pattern).
func MustParse(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(fmt.Sprintf("invalid URL %q: %v", raw, err))
	}
	return u
}
```

```go
// Avoid: panic escaping a package boundary.
func Process(items []string) []string {
	// This panic can escape — callers won't expect it.
	if len(items) == 0 {
		panic("empty items")
	}
	// ...
}
```

## Examples

```go
var ErrAuthRequired = errors.New("authentication required")

func connect(ctx context.Context, url string) (*Session, error) {
	s, err := sdk.Connect(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w", url, err)
	}
	return s, nil
}
```

```go
// Prefer errors.AsType for concrete types.
if ee, ok := errors.AsType[*exitError](err); ok {
	os.Exit(ee.code)
}
```

```go
// Prefer errors.As for interface types.
var netErr net.Error
if errors.As(err, &netErr) && netErr.Timeout() {
	return true
}
```

```go
// Avoid double handling: log OR return, not both.
if err != nil {
	logger.Error("scan failed", "server", srv.Name, "err", err)
	return fmt.Errorf("scan %s: %w", srv.Name, err)
}
```
