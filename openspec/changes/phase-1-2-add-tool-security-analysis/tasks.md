## 1. Tool description analysis

- [ ] 1.1 Define injection patterns in `internal/scanner/analysis.go`: system prompt hijacking, role-switching, base64 blocks, external URLs
- [ ] 1.2 Implement `analyzeToolDescription(tool mcp.Tool) []Result` — run all patterns against `Tool.Description`
- [ ] 1.3 Add empty-description detection: INFO finding when description is empty or whitespace-only

## 2. Tool capability classification

- [ ] 2.1 Implement `classifyToolCapabilities(schema map[string]any) []string` — parse properties for filesystem/network/shell/database indicators
- [ ] 2.2 Flag shell-capable tools at HIGH severity
- [ ] 2.3 Flag multi-capability tools with combined capability list
- [ ] 2.4 Detect overly broad schemas: no properties defined or `additionalProperties: true` with no constraints

## 3. Tool shadowing detection

- [ ] 3.1 Implement `detectToolShadowing(allServersTools map[string][]mcp.Tool) []Result` — same-name tools across servers with conflicting descriptions/schemas
- [ ] 3.2 Report shadowing at MEDIUM severity with conflicting server names in finding text

## 4. Tool return value analysis

- [ ] 4.1 Add prompt injection patterns to `evalToolTextBlock` in `analysis.go` alongside existing credential checks
- [ ] 4.2 Classify injection in tool responses at HIGH severity (tool is poisoning the AI client)

## 5. Probe pipeline integration

- [ ] 5.1 Call tool description analysis after `ListTools` succeeds in `runMCPProbes` (dynamic.go)
- [ ] 5.2 Call tool capability classification on all discovered tools
- [ ] 5.3 Add `--tool-analysis` / `--no-tool-analysis` flag to CLI (default: enabled)
- [ ] 5.4 Run tool shadowing detection after all servers' tools are collected

## 6. Tests

- [ ] 6.1 Test description injection patterns with crafted descriptions (each pattern class)
- [ ] 6.2 Test capability classification with varied InputSchema fixtures
- [ ] 6.3 Test shadowing detection with 2-server, 3-server, and no-conflict cases
- [ ] 6.4 Test return value injection detection integrated with existing SSRF analysis
- [ ] 6.5 Test empty description flagging and overly broad schema detection
