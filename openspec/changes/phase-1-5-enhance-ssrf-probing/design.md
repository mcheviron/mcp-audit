## Context

Current SSRF probing: 14 hardcoded targets, GET only, no redirect following, no blind SSRF, no DNS rebinding. Missing Azure/DigitalOcean/Oracle metadata endpoints. Limited to direct HTTP probes — can't detect servers that make outbound calls asynchronously.

## Goals / Non-Goals

**Goals:** Callback listener for blind SSRF, cloud metadata expansion (Azure, DO, Oracle), POST/PUT method probes, header-based SSRF (`X-Forwarded-Host`, `Host`, `Referer`), redirect chain following (up to 5 hops), DNS rebinding probe, `--probe-depth` levels, `--targets-file` support.

**Non-Goals:** Full OAST framework, WebSocket/gRPC probes, exploitation payloads.

## Decisions

### Callback listener: embedded HTTP server on random port

Start `net/http.Server` on `:0` (random port), inject `http://<local-ip>:<port>/callback` into probe args. When callback receives GET, record finding. Shutdown after probe phase. Timeout: 30s wait after last probe.

### Probe depth levels

- `basic` (default): current behavior, 14 GET targets
- `extended`: +POST/PUT methods, +header variants, +redirect following, +Azure/DO/Oracle targets
- `full`: +callback listener, +DNS rebinding

### DNS rebinding: resolve controlled hostname

Use a hostname that resolves to both external and internal IPs (e.g., `1.0.0.127.1pointeruhj4t0nk7rl9.z.okd.sx` — publicly available rebinding service). Probe GET to this hostname; if server follows to internal IP, flag.

## Risks

- Callback server briefly listens on network → Mitigation: bind to loopback only, 30s max lifetime
- DNS rebinding uses external service → Mitigation: document dependency, allow disable via `--probe-depth basic`
