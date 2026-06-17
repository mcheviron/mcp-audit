## Why

Current SSRF probing is narrow: GET-only, 14 hardcoded targets missing major cloud providers (Azure, DigitalOcean, Oracle Cloud), no blind SSRF detection via callback listener, no DNS rebinding probes, no redirect chain analysis beyond first hop. Academic papers and CSA guidance confirm modern SSRF attacks exploit these vectors. A production auditor must detect SSRF across the full attack surface.

## What Changes

- Embed callback listener: start local HTTP server on random port, inject callback URL into probe args, detect outbound connections
- Add Azure metadata endpoint (`169.254.169.254` with `Metadata: true` header), DigitalOcean (`169.254.169.254`), Oracle Cloud (`169.254.169.254`)
- DNS rebinding probes: resolve hostname that cycles between external and internal IPs
- HTTP method expansion: POST, PUT probes to catch SSRF in non-GET handlers
- Header-based SSRF: inject internal targets into `X-Forwarded-Host`, `Host`, `Referer` headers
- Redirect chain following: follow up to 5 redirects, detect internal redirect at any hop
- `--probe-depth` flag: `basic` (current), `extended` (+methods+headers), `full` (+callback+DNS rebinding)
- File-based probe target lists (`--targets-file`)

## Capabilities

### Modified Capabilities

- `dynamic-ssrf-probing`: Extend probe target list, HTTP methods, header injection, redirect chain analysis, callback-based blind SSRF detection, DNS rebinding probes, and probe depth configuration.

## Impact

- `internal/scanner/dynamic.go` — callback listener, expanded probe targets, method/header variants, redirect following
- `internal/scanner/analysis.go` — blind SSRF callback analysis, DNS rebinding detection
- `main.go` — `--probe-depth`, `--targets-file`, `--callback-port` flags

## Non-Goals

- Full OAST (out-of-band application security testing) framework — callback listener is minimal
- WebSocket or gRPC SSRF probes
- Exploitation or data exfiltration — detection only
