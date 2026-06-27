## Context

`analyzeAdversarialResponse` in `internal/scanner/adversarial.go:112` matches two regex sets (`sysPromptPatterns`, `roleSwitchPatterns`) against raw response text. The function takes only `text string` and returns the matched indicator category. It has no access to:

- The tool being probed (`toolName`)
- The tool's description (purpose)
- The probe text that was sent
- Whether the response is an error vs. successful result

The blind regex match produces false positives when responses legitimately contain URL-like strings, ID tokens, or error messages that echo rejected input. Recent probe run: 4 HIGH findings, all false positives.

## Goals / Non-Goals

**Goals:**
- Reduce false positive rate by ~70% on probe runs with mixed tool types
- Maintain detection of true extraction/injection vulns (no regression on known positives)
- Preserve trust score semantics — only change which probe responses count as "succeeded"
- Single-function extension, no new dependencies

**Non-goals:**
- Not adding new detection techniques (no LLM-based analysis, no ML)
- Not changing the probe library content
- Not changing trust score formula

## Decisions

**Decision: Extend `analyzeAdversarialResponse` signature to accept context**

New signature: `analyzeAdversarialResponse(text, probeText, toolName, toolDesc string) MatchResult` where `MatchResult` contains `{Indicator string, Confidence float64}`. Callers in `recordAdversarialProbeResult` already have all four values.

Alternative: Pass a context struct. Rejected — single function call site, struct is overkill.

**Decision: Confidence = base_score × echo_factor × purpose_factor**

- `base_score`: 1.0 if match found, 0.0 otherwise
- `echo_factor`: 1.0 if no overlap with probe text, down to 0.2 if match contains probe text fragments
- `purpose_factor`: 1.0 for execute/write tools, 0.6 for read-only, 0.3 for URL/document retrieval

Match emits HIGH only when confidence ≥ 0.5. Below 0.5, returns INFO with "review manually" note.

Alternative: Hard-coded suppression lists. Rejected — fragile, requires constant maintenance.

**Decision: Echo detection uses longest-common-substring ratio**

Compute LCS between matched substring and probe text. If LCS > 60% of match length, treat as echo and apply echo_factor 0.2.

Alternative: Simple substring contains. Rejected — too strict (a single shared word doesn't mean echo); a clever probe rephrases, so substring match would miss echoes.

**Decision: Purpose classification by keyword in tool description**

Keywords for URL/document retrieval: `search`, `lookup`, `fetch`, `get`, `list`, `read`, `find`, `query`, `retrieve`. If tool description contains any of these and tool name is non-mutating (no `delete`, `execute`, `write`, `update`, `set`), purpose_factor = 0.3.

Alternative: Per-tool classifier. Rejected — over-engineered for a stopgap.

## Risks / Trade-offs

- [True positive gets suppressed] → Mitigation: emit at INFO with `confidence=0.65` and a note "low confidence, review manually". User can grep for these. Trust score treats them as successes still (conservative).

- [Purpose keywords too broad — "delete-search" matches "search"] → Mitigation: explicit deny-list of mutating verbs. If tool description or name contains `delete`/`execute`/`write`/`update`/`set`/`remove`/`create`, force purpose_factor back to 1.0.

- [Confidence threshold 0.7 arbitrary] → Mitigation: expose as constant `minConfidenceForHIGH = 0.7` for easy tuning. Document trade-off in design comment.

- [Echo detection adds latency per match] → Mitigation: only computed when base regex match exists. Most responses don't match → no overhead.

## Migration Plan

1. Land with confidence threshold 0.7. Measure false positive rate in next probe run.
2. If too aggressive (real positives suppressed), tune threshold down to 0.5.
3. If too lenient (false positives still high), expand purpose keywords.

Rollback: revert `analyzeAdversarialResponse` signature and callers. No schema changes.