## Why

Current tool is one-shot: run, get report, exit. For production use, users need: (1) continuous monitoring — re-scan when MCP configs change, (2) proxy mode — sit between AI client and MCP server to audit all traffic in real-time. Both are listed as post-MVP in PLAN.md. Proxy mode enables runtime detection of attacks that static/probe approaches miss: behavioral drift, tool poisoning in live responses, cross-request patterns.

## What Changes

- **Daemon mode**: `mcp-audit watch` — fsnotify on discovered config files, re-scan on change, option to run probes on new/changed servers
- **Proxy mode**: `mcp-audit proxy --listen :8080 --target http://real-server:3000` — transparent MCP proxy that logs all JSON-RPC traffic, inspects tool descriptions and responses in real-time, and can block dangerous calls
- Daemon: configurable poll interval (`--watch-interval`, default 30s), optional notification command on finding (`--on-finding`)
- Proxy: request/response logging, tool description inspection on initial `tools/list`, response inspection on each `tools/call`, optional blocking mode (`--block-critical`)
- Both modes use existing scanner/analysis pipeline

## Capabilities

### New Capabilities

- `daemon-mode`: Continuous filesystem watching and re-scanning of MCP config files with configurable notification hooks.
- `proxy-mode`: Transparent MCP proxy auditing all JSON-RPC traffic between AI client and MCP server with real-time inspection and optional blocking.

### Modified Capabilities

- `dynamic-ssrf-probing`: Extend MCP client to support proxy-mode request/response inspection callbacks.

## Impact

- `internal/daemon/` — new package: `watcher.go` (fsnotify), `scheduler.go` (re-scan loop)
- `internal/proxy/` — new package: `proxy.go` (HTTP reverse proxy), `inspector.go` (traffic analysis)
- `main.go` — `watch` and `proxy` subcommands with flags
- `go.mod` — `golang.org/x/fsnotify` for daemon mode (or use `fsnotify` from stdlib-compatible approach)

## Non-Goals

- gRPC proxy (MCP doesn't use gRPC)
- Stdio proxy mode (complex, requires ptrace-like interception)
- Alerting integrations (Slack, PagerDuty) — notification command hook covers this
- Configuration hot-reload in daemon mode
