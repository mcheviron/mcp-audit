---
title: Code Shape And Control Flow
---

# Code Shape And Control Flow

## Purpose

Favor straightforward control flow so behavior is easy to verify and maintain.

## When To Apply

Use for new functions, refactors, and reviews where readability or branching complexity is in scope.

## Mandatory Rules

- Keep functions focused on one responsibility.
- Prefer early returns for invalid states and errors to keep the happy path flat.
- Avoid unnecessary `else` after `return`, `continue`, or `break`.
- Keep nesting shallow; split complex branches into helper functions with clear names.
- Use `switch` for multi-branch decisions on the same subject.
- Keep declarations (`const`, `type`, package vars) near file top and group related logic together.
- Reduce parameter explosion with config/options structs when call sites become unclear.

## Import Grouping

Group imports in this order, separated by blank lines:

1. Standard library
2. Other external packages
3. (If applicable) Protocol buffer imports
4. Side-effect imports (`import _`)

```go
import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	_ "net/http/pprof"
)
```

## Literal Formatting

- Specify field names in struct literals for types defined outside the current package.
- For package-local types, field names are optional but recommended for clarity.
- Place the closing brace on a line with the same indentation as the opening brace.
- Multi-line literals should end with a comma and the closing brace on the next line.
- Zero-value fields may be omitted from struct literals when clarity is not lost.
- Table-driven test structs benefit from explicit field names, especially when zero values are unrelated to the test case.

```go
// Good: field names for external types, trailing comma, brace alignment.
req := &http.Request{
	Method: http.MethodGet,
	URL:    parsedURL,
	Header: headerMap,
}
```

```go
// Good: omit zero-value fields when obvious.
srv := config.ServerEntry{
	Name: "primary",
	URL:  "https://example.com",
}
```

## Examples

```go
func Validate(req Request) error {
	if req.UserID == "" {
		return ErrMissingUserID
	}
	if req.Amount <= 0 {
		return ErrInvalidAmount
	}
	return nil
}
```

```go
// Avoid deep nesting when a guard clause works.
func Validate(req Request) error {
	if req.UserID != "" {
		if req.Amount > 0 {
			return nil
		} else {
			return ErrInvalidAmount
		}
	}
	return ErrMissingUserID
}
```
