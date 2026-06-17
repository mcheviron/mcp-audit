## Context

Response analysis: 4 regex patterns on 4KB bodies. No semantic understanding, no structural analysis, no behavioral comparison. MCPShield paper (May 2026): metadata-only detection plateaus at 0.64 AUROC.

## Goals / Non-Goals

**Goals:** Keyword-frequency scoring, entropy calculation, response classification (metadata/error/data/binary), structural comparison to schema, behavioral drift between probes, timing analysis, configurable response limit (default 64KB).

**Non-Goals:** ML/embeddings, external services, LLM analysis.

## Decisions

### Scoring: weighted keyword frequency

Score responses 0.0-1.0 based on presence/absence of security-relevant keywords normalized by response size. High scores trigger deeper regex analysis. Low-scoring responses are classified as PASS more aggressively.

### Entropy: Shannon entropy on response body

High entropy (>7.5 bits/byte) → possibly encrypted or compressed data (benign). Low entropy (<3.0) → structured text, possible metadata. Very low entropy (<1.5) → repetitive pattern, possible exfiltration marker.

### Structural analysis: compare to expected schema

If tool's InputSchema defines output structure (rare but possible), compare response structure. Flag structural mismatches as INFO.

### Timing: flag outliers

Record response times per probe. Flag responses >2 stddev from mean as potential SSRF (internal services often respond faster). Flag timeout-only servers as suspicious (may be filtering probes).
