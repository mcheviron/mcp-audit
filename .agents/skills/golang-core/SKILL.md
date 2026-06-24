---
name: golang-core
description: Go implementation, refactor, review, and design guidance for mcp-audit. Covers naming, control flow, context, errors, safety, concurrency, performance, testing, and modern idioms.
---

# Golang Core Skill

Go guidance for correctness, maintainability, and clarity in mcp-audit.

This skill defines language-level rules. Project-specific constraints (zero comments, stdlib-only, 500-line files, 70-line functions) live in `CLAUDE.md` and take precedence when they conflict.

## How to Apply This Skill

1. Identify whether the task changes Go code, design, or behavior.
2. Always read the core rule files listed below.
3. Add conditional rule files only when the task touches those concerns.
4. Apply these rules as mandatory unless `CLAUDE.md` explicitly overrides them.

### Always Read

- `rules/api-shape-and-naming.md`
- `rules/code-shape-and-control-flow.md`
- `rules/context-propagation.md`
- `rules/error-handling.md`
- `rules/safety-and-zero-values.md`
- `rules/performance-and-data-structures.md`
- `rules/testing-conventions.md`
- `rules/modern-go.md`

### Conditional Reads

- `rules/concurrency-lifecycle.md` for goroutines, channels, worker pools, or shutdown paths.

## Priority and Conflict Resolution

- `golang-core` owns generic Go rules.
- `CLAUDE.md` owns project-specific constraints (dependency policy, comment policy, file/function limits).
- When both apply, follow `CLAUDE.md` for project constraints and `golang-core` for language-level decisions.

## Reference Index

| File | Focus |
|---|---|
| `rules/api-shape-and-naming.md` | Identifier naming, API shape, constructors |
| `rules/code-shape-and-control-flow.md` | Function shape, branching, flow clarity |
| `rules/context-propagation.md` | Context ownership, timeouts, cancellation |
| `rules/error-handling.md` | Wrapping, classification, logging boundary discipline |
| `rules/safety-and-zero-values.md` | Footgun prevention and defensive data handling |
| `rules/performance-and-data-structures.md` | Measure-first performance and low-regret optimizations |
| `rules/testing-conventions.md` | Test structure, failure messages, got/want style, table tests |
| `rules/modern-go.md` | Current Go idioms and replacement of outdated patterns |
| `rules/concurrency-lifecycle.md` | Goroutine lifecycle, channel ownership, cancellation paths |
