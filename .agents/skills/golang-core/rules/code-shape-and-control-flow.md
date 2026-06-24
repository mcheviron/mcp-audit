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
