---
title: API Shape And Naming
---

# API Shape And Naming

## Purpose

Keep APIs predictable and readable at the call site.

## When To Apply

Use for any new or modified package, type, function, method, or exported identifier.

## Mandatory Rules

- Use `camelCase` for unexported identifiers and `PascalCase` for exported identifiers.
- Keep acronym casing consistent: `ID`, `URL`, `HTTP`, `JSON`.
- Avoid names that collide with builtins (`len`, `error`) or imported packages.
- Do not encode types in names (`userMap`, `countInt`) unless disambiguating a conversion value.
- Export sparingly. Default to unexported names unless cross-package use is required.
- Avoid stutter at call sites (`config.New()` over `config.NewConfig()`).
- Constructors should follow `NewX` by default; use `MustX` only for fail-fast setup.
- Getter names should not use `Get` (`Address()`), and mutation methods should use `Set` when mutation is intended.
- Keep receiver names short and consistent across methods of the same type.
- Use import aliases only when needed for collision resolution.
- Boolean names should read like predicates (`isReady`, `hasAccess`, `canRetry`).

## Receiver Type Selection

- Use pointer receiver when mutating the receiver, when the struct contains uncopyable fields (e.g., `sync.Mutex`), or when in doubt.
- Use value receiver for slices/maps/channels that are not resliced or reallocated, for small value-type structs with no uncopyable fields, and for built-in types that do not need modification.
- Prefer all methods on a type to be either all-pointer or all-value; mixing is allowed only when semantically justified.
- Correctness wins over performance or simplicity.

## Variable Name Length

- Length should be proportional to scope size and inversely proportional to usage frequency.
- Baseline: 1–7 lines = small scope, 8–15 = medium, 15–25 = large, 25+ = very large.
- Do not drop letters to save typing (prefer `Sandbox` over `Sbx`).
- Omit type-like words from names (`users` not `userSlice`).
- Omit words already clear from the surrounding context (package name, method name, parameter names).
- Single-letter names: limit to when the full word is obvious and repetition would be excessive. Common conventions: `r` for `io.Reader`/`*http.Request`, `w` for `io.Writer`/`http.ResponseWriter`, `i` for loop indices.

## Interface Design

- Avoid creating interfaces until a real need exists; do not introduce abstractions preemptively.
- The consumer of the interface defines it, not the implementer.
- Keep interfaces small; prefer one or two methods.
- Functions should accept interfaces as parameters but return concrete types.
- Do not wrap clients (e.g., HTTP clients, SDK clients) in manual interfaces for abstraction or testing.
- Do not define test-double interfaces solely for testing; prefer testing via the public API or using real transports with test servers.
- Keep interface types unexported if only used within the package.

## Examples

```go
type Scanner struct{}

func NewScanner(opts ...Option) *Scanner { return &Scanner{} }
func (s *Scanner) IsReady() bool         { return true }
```

```go
// Avoid
func NewScannerConfig(scannerOpts ScannerOptionsInterface) *scanner_config { return nil }
func (scanner *scanner_config) GetIsReady() bool { return false }
```

```go
// Interface: consumer defines it, small, unexported if internal.
type probeTarget interface {
	Probe(ctx context.Context) ([]Result, error)
}

func runProbe(ctx context.Context, target probeTarget) ([]Result, error) {
	return target.Probe(ctx)
}
```

```go
// Avoid: wrapping an SDK client in a manual interface for testing.
type MCPClient interface {
	ListTools(ctx context.Context) ([]Tool, error)
	CallTool(ctx context.Context, name string, args map[string]any) (any, error)
}
```

```go
// Variable name length proportional to scope.
func process(items []string) []string { // small scope: short names
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, normalize(item))
	}
	return out
}

func buildReport(servers []config.ServerEntry, results map[string][]scanner.Result) report.Report { // large scope: descriptive names
	filteredResults := filterCritical(results)
	summary := summarize(filteredResults)
	return report.New(servers, filteredResults, summary)
}
```
