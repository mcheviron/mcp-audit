## Context

Tool is one-shot. Users want continuous monitoring and real-time traffic inspection. PLAN.md lists both as post-MVP.

## Goals

Daemon mode: fsnotify on config files, re-scan on change, optional notification command. Proxy mode: transparent HTTP reverse proxy, JSON-RPC inspection, real-time tool description/response analysis, optional blocking. Both reuse existing scanner/analysis pipeline.

## Decisions

### Daemon: fsnotify on config file directories

Watch each discovered config file's parent directory for writes. Debounce 500ms before re-scan (config editors often write multiple times). Re-scan static analysis on change; optionally re-probe new servers.

Alternative: poll `os.Stat` every N seconds. Rejected — fsnotify is more responsive and uses fewer resources for idle periods.

### Proxy: httputil.ReverseProxy with custom Director

`net/http/httputil.ReverseProxy` handles streaming, headers, and connection pooling. Custom `Director` modifies request URL to target. Custom `ModifyResponse` inspects response body for JSON-RPC content, extracts tool lists and call results, runs analysis pipeline inline.

### Proxy blocking: response rewrite

When `--block-critical` is set and analysis finds CRITICAL, proxy returns MCP error response `{"jsonrpc": "2.0", "error": {"code": -32000, "message": "Blocked by mcp-audit: <reason>"}}` instead of forwarding the server response.

### No stdio proxy

Proxying stdio requires intercepting subprocess stdin/stdout, which is OS-specific and fragile. Document as limitation. Users with stdio servers should use `mcp-audit probe` instead.

## Risks

- **Proxy adds latency** → Mitigation: analysis runs on response read, not blocking the stream. Blocking mode adds latency only when finding is CRITICAL.
- **fsnotify not in stdlib** → Mitigation: use `golang.org/x/fsnotify` (same org as `x/sync` already in go.mod).
