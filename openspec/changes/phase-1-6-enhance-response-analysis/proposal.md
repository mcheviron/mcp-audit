## Why

Current response analysis uses four regex patterns on truncated 4KB bodies. Academic research (MCPShield paper, May 2026) proves metadata-only detection plateaus at ~0.64 AUROC — content analysis pushes above 0.89. Production tools (MindGuard 94-99% precision, ShieldNet 0.995 F1) all use content inspection. The tool's regex-only approach misses semantic attacks: benign-looking responses containing encoded malicious content, multi-step exfiltration patterns, and behavioral anomalies where response structure doesn't match declared tool purpose.

## What Changes

- Implement keyword-frequency and entropy-based response scoring for anomaly detection
- Add structural analysis: compare response structure to declared InputSchema output expectations
- Add behavioral drift detection: flag when response patterns change significantly between probes
- Expand from 4KB to configurable response read limit (default 64KB, `--max-response` flag)
- Implement response classification: metadata, error, data, binary — different analysis per class
- Add timing analysis: flag unusually fast or slow responses (potential SSRF to fast internal services)
- All heuristics — no external ML dependencies. Stdlib `math`, `sort`, `container` only.

## Capabilities

### Modified Capabilities

- `dynamic-ssrf-probing`: Extend response analysis pipeline with content-based scoring, structural analysis, behavioral drift, response classification, and timing analysis. Expand response read limit.

## Impact

- `internal/scanner/analysis.go` — new analysis functions: `scoreResponse`, `classifyResponse`, `analyzeStructure`, `detectBehavioralDrift`, `analyzeTiming`
- `internal/scanner/dynamic.go` — increase response limit, capture timing metrics, pass to new analysis
- `main.go` — `--max-response` flag (default 64KB)

## Non-Goals

- LLM-based or embedding-based semantic analysis (external dependencies)
- Machine learning model training or inference
- External service integration for content classification
