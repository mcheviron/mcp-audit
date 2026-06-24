---
title: Context Propagation
---

# Context Propagation

## Purpose

Ensure cancellation and timeouts flow consistently through I/O boundaries.

## When To Apply

Use for HTTP calls, subprocess management, MCP client operations, and any blocking work.

## Mandatory Rules

- For I/O or request-scoped work, accept `context.Context` as the first parameter.
- Propagate the incoming context through all downstream calls.
- Do not replace live request context with `context.Background()` inside request paths.
- Do not store context in structs; pass it explicitly per call.
- Derive child contexts with timeouts/deadlines when needed and always call `cancel`.
- Check `ctx.Done()` in long-running loops and blocking selects.
- Use context-aware APIs for external requests and subprocess operations.

## Examples

```go
func probeServer(ctx context.Context, srv config.ServerEntry) ([]Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	client, err := mcp.NewAutoClient(ctx, srv.URL, ...)
	if err != nil {
		return nil, err
	}
	return client.ListTools(ctx)
}
```

```go
// Avoid: dropping request context and losing cancellation signals.
func probeServer(_ context.Context, srv config.ServerEntry) ([]Result, error) {
	client, err := mcp.NewAutoClient(context.Background(), srv.URL, ...)
	...
}
```
