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
