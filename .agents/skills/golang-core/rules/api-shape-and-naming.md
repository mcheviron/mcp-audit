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
