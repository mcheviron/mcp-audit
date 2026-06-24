---
title: Concurrency Lifecycle
---

# Concurrency Lifecycle

## Purpose

Keep concurrent code safe, cancellable, and easy to shut down cleanly.

## When To Apply

Use for goroutines, channels, worker pools, fan-out/fan-in flows, and background tasks. In mcp-audit this applies primarily to `internal/scanner/dynamic.go` (parallel server probing), `internal/daemon/watcher.go`, and `cmd/mcp-audit/signal.go`.

## Mandatory Rules

- Every goroutine must have a clear owner responsible for its lifecycle.
- Every goroutine must have an explicit exit path (context cancellation, channel close, or bounded work).
- Watch `ctx.Done()` in blocking loops and `select` statements.
- Only the sender side closes a channel.
- Prefer `errgroup` for related concurrent tasks that should fail or cancel together.
- Avoid `time.After` in loops; use `time.NewTimer` or `time.NewTicker` and stop them.
- Avoid unbounded goroutine creation under load; bound concurrency.
- Protect shared mutable state with synchronization primitives.
- Prefer synchronous functions over asynchronous ones; keep goroutines localized to aid reasoning about lifetimes, avoid leaks and data races, and simplify testing.
- Specify channel direction in function signatures where possible (`chan<-` for send-only, `<-chan` for receive-only) to prevent casual programming errors.

```go
// Good: synchronous function; caller decides concurrency.
func probeAll(ctx context.Context, servers []config.ServerEntry) ([]Result, error) {
	var all []Result
	for _, srv := range servers {
		results, err := probeServer(ctx, srv)
		if err != nil {
			return nil, err
		}
		all = append(all, results...)
	}
	return all, nil
}
```

```go
// Good: directional channel signatures.
func fanOut(ctx context.Context, jobs <-chan Job) <-chan Result {
	results := make(chan Result)
	go func() {
		defer close(results)
		for job := range jobs {
			select {
			case <-ctx.Done():
				return
			case results <- process(job):
			}
		}
	}()
	return results
}
```

## Examples

```go
g, ctx := errgroup.WithContext(ctx)
for _, srv := range servers {
	srv := srv
	g.Go(func() error {
		return probeServer(ctx, srv)
	})
}
if err := g.Wait(); err != nil {
	return fmt.Errorf("probe: %w", err)
}
```

```go
// Avoid spawning work without cancellation or ownership.
for _, srv := range servers {
	go probeServer(context.Background(), srv)
}
```
