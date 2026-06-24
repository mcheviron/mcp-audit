## Context

Current analysis (`internal/scanner/tool_analysis.go`, `content.go`) is pure regex: prompt injection patterns, capability classification by property name, empty description checks. Each check produces a Finding with severity. No quantitative scoring, no anomaly detection, no aggregated risk.

MCP Verify tiers by latency budget: Layer 1 <10ms regex, Layer 2 <50ms scoring/anomaly, Layer 3 500-2000ms LLM. MCTS dual-scores with legacy and v2 multi-factor engines for gradual migration. mcp-audit needs at minimum Layer 2 to stay competitive.

## Goals / Non-Goals

**Goals:**
- Deterministic heuristic scoring (description entropy, naming consistency, schema complexity)
- Weighted multi-factor composite score 0-100
- CI gate flags for score thresholds
- Score display in all output formats
- Drop-in: existing finding pipeline unchanged, scores added alongside

**Non-Goals:**
- LLM/ML models (Layer 3 extension point only — Go interface, no implementation)
- Persistent score history
- Per-tool historical comparison

## Decisions

### Decision 1: Heuristics as pure functions operating on existing data

Each heuristic is a `func(tools []mcp.Tool, findings []Finding) ScoreResult` — stateless, no I/O, no network. Takes the output of Layer 1 and enriches it. This means Layer 2 never blocks Layer 1 producing results.

**Alternative:** Pipeline stages with channels. Rejected — over-engineering for a sequential two-layer pipeline where failure isolation matters more than parallelism.

### Decision 2: Factor weights hardcoded with config override

Default weights: typosquat 0.25, CVE 0.30, capability 0.20, description 0.15, network 0.10. Configurable via `--score-weights` flag accepting comma-separated float list. Order matches factor enum. Sum must equal 1.0.

**Alternative:** YAML config file for weights. Rejected — needless complexity for 5 numbers.

### Decision 3: Score stored on Result, not Finding

`Result.Score` is a `float64` 0-100. Individual findings keep severity. This separates "what happened" (findings) from "how risky overall" (score). SARIF output maps score to `rank` property.

### Decision 4: Shannon entropy computed on character distribution

`H = -sum(p_i * log2(p_i))` over ASCII character frequencies, normalized to 0-100 by dividing by log2(distinct chars). O(n) per description, fast enough for Layer 2 latency budget (<50ms for 100 tools × 500 chars each).

## Risks / Trade-offs

- [Risk] Heuristic scores may diverge from user-perceived risk → Mitigation: all individual factor scores visible in verbose output, user can tune weights
- [Risk] CI gates using scores may break existing CI pipelines that only checked severity → Mitigation: gates default off; `--min-security-score` must be explicitly set
