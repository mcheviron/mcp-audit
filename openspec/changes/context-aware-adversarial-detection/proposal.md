## Why

The adversarial probe analyzer (`internal/scanner/adversarial.go:analyzeAdversarialResponse`) matches system-prompt and role-switch regex patterns against raw response text. These patterns fire on:

1. **Echoed input** — validation errors that include the rejected input (e.g., `"Invalid repoName format: 'http://127.0.0.1:8080/'"` matches `http://` patterns indirectly)
2. **Legitimate URL-bearing responses** — search tools (openaiDeveloperDocs), doc lookup (deepwiki), and GitHub search (gh_grep) return URLs/paths by design
3. **Non-tool responses** — error messages, status indicators, transport-level metadata that aren't tool output

A probe run produces 4 HIGH findings that are all false positives. Trust scores become unreliable because false-positive successes artificially lower the score. Reviewers waste time chasing non-issues while potentially missing real injection vulns drowned in noise.

## What Changes

- Add tool-purpose classification (read/write/execute) to the probe analysis path
- Add an echo-detection pass that recognizes when matched text comes from the probe input rather than server state
- Suppress pattern matches on responses whose matched text overlaps with the original probe text by more than 60%
- Suppress pattern matches on responses from tools whose description indicates URL/document retrieval
- Add a confidence score per match and only emit HIGH findings when confidence ≥ 0.7
- Demote low-confidence matches to INFO with a "review manually" note

## Capabilities

### Modified Capabilities

- `adversarial-probes`: Pattern matching in `analyzeAdversarialResponse` becomes context-aware, considering tool description and input echo. HIGH severity is reserved for high-confidence matches. Low-confidence matches are reported at INFO.

## Impact

- `internal/scanner/adversarial.go` — extend `analyzeAdversarialResponse` with context awareness, add confidence scoring
- `internal/scanner/adversarial_test.go` — new test cases for echo suppression and tool-purpose filtering
- `openspec/specs/adversarial-probes/spec.md` — modified "Extraction/Injection probe detected" requirements

## Non-goals

- Not replacing regex matching entirely (long-term Option C, separate work)
- Not adding new probe categories
- Not changing trust score formula
- Not changing probe library content