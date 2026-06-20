# dynamic-ssrf-probing Specification

## Purpose
Dynamic SSRF probing via direct HTTP requests and MCP JSON-RPC tool calls against internal and cloud metadata endpoints.
## Requirements
### Requirement: MCP JSON-RPC handshake
The system SHALL implement a minimal MCP JSON-RPC 2.0 client supporting the `initialize` request and response to establish a session with an MCP server before probing. The client SHALL support stdio, SSE, and Streamable HTTP transports. Transport selection SHALL be automatic based on server config.

#### Scenario: Successful HTTP handshake
- **WHEN** connecting to a valid MCP server over Streamable HTTP
- **THEN** the client sends `initialize` with protocol version "2024-11-05" and receives a valid response with server capabilities

#### Scenario: Successful stdio handshake
- **WHEN** connecting to a valid MCP server via stdio subprocess
- **THEN** the client sends `initialize` as a JSON-RPC line to stdin and receives a valid response from stdout

#### Scenario: Successful SSE handshake
- **WHEN** connecting to a valid MCP server over SSE
- **THEN** the client discovers the message endpoint via `/sse`, POSTs `initialize`, and receives a valid response via the event stream

#### Scenario: Handshake timeout
- **WHEN** the MCP server does not respond within the transport-specific timeout (5s HTTP, 5s stdio, 10s SSE)
- **THEN** the probe records a connection timeout and moves to the next server

#### Scenario: Non-MCP endpoint
- **WHEN** the endpoint returns non-JSON or a non-MCP response
- **THEN** the probe records an error and skips SSRF testing for that server (cannot determine protocol support)

### Requirement: Transport-aware server collection
The system SHALL collect all discoverable MCP servers for dynamic probing regardless of transport type. Servers with `Command` set (stdio) and servers with `URL` set (HTTP/SSE) SHALL both be included in the probe pipeline.

#### Scenario: Stdio server included in probe
- **WHEN** a discovered config contains a server with `command: "npx"` and `args: ["-y", "@scope/mcp-server"]`
- **THEN** that server is included in the dynamic probe phase via stdio transport

#### Scenario: SSE server included in probe
- **WHEN** a server URL supports only SSE and Streamable HTTP handshake fails
- **THEN** the server is probed via SSE transport fallback

#### Scenario: Transport failures logged but don't block
- **WHEN** a server cannot be reached via any transport
- **THEN** an INFO finding is recorded with the transport error
- **AND** probing continues with the next server

### Requirement: Auth-aware probing
The system SHALL apply authentication configuration (headers, tokens, certificates) when connecting to MCP servers. Servers requiring auth that are missing credentials SHALL be reported with an INFO finding noting the auth gap rather than a connection error.

#### Scenario: Authenticated probe succeeds
- **WHEN** `ServerEntry.AuthToken` is set and the server requires Bearer auth
- **THEN** the MCP handshake and SSRF probes complete using the provided token

#### Scenario: Missing auth detected
- **WHEN** a server returns HTTP 401 or 403 and no auth is configured
- **THEN** an INFO finding reports "server requires authentication, none configured"

### Requirement: SSRF payload delivery
The system SHALL send crafted `tools/call` requests to each probed MCP server where the tool arguments contain URLs targeting internal and cloud metadata endpoints.

#### Scenario: AWS metadata probe
- **WHEN** probing a server that makes HTTP requests based on tool arguments
- **THEN** the probe sends a tool call with a URL argument of `http://169.254.169.254/latest/meta-data/`

#### Scenario: GCP metadata probe
- **WHEN** probing a server that supports URL-fetching tools
- **THEN** the probe sends a tool call targeting `http://metadata.google.internal/computeMetadata/v1/`

#### Scenario: IPv6 loopback probe
- **WHEN** performing a full probe sweep
- **THEN** the probe includes `http://[::1]/` in the target list

### Requirement: Safe probing constraints
The system SHALL enforce safety limits: maximum 5 seconds per probe, configurable response read limit (default 64KB via `--max-response`), maximum 10 concurrent probes, minimum 100ms between probes to the same host.

#### Scenario: Probe timeout enforced
- **WHEN** a probe does not complete within 5 seconds
- **THEN** the probe is cancelled and the finding is recorded with the timeout noted

#### Scenario: Response truncated
- **WHEN** a probe response exceeds the configured `--max-response` limit (default 64KB, max 1MB)
- **THEN** only up to the configured byte count is read and analyzed; the connection is closed

#### Scenario: Rate limiting between same-host probes
- **WHEN** two probes target the same host
- **THEN** the second probe starts no sooner than 100ms after the first completes

### Requirement: Response analysis
The system SHALL analyze probe responses for indicators of successful SSRF: cloud metadata content, internal HTTP response bodies, redirect chains to internal IPs, connection outcomes, AND prompt injection patterns in tool return values. Prompt injection detection in tool responses SHALL use the same pattern set defined in `tool-security-analysis`.

#### Scenario: Cloud metadata returned — CRITICAL
- **WHEN** a probe response contains AWS access key IDs or IAM role credentials
- **THEN** the finding is classified as CRITICAL severity

#### Scenario: Redirect to internal IP — HIGH
- **WHEN** the server follows a redirect to `http://192.168.1.1/admin` and returns that response body
- **THEN** the finding is classified as HIGH severity

#### Scenario: Connection refused — MEDIUM
- **WHEN** the probe to `http://169.254.169.254/` results in "connection refused"
- **THEN** the finding is classified as MEDIUM severity (firewall likely blocked, but server attempted connection)

#### Scenario: Open redirect detected — LOW
- **WHEN** the server returns a 3xx redirect to an internal IP but the probe does not follow it
- **THEN** the finding is classified as LOW severity (open redirect, no internal data exfiltrated)

#### Scenario: Prompt injection in tool response — HIGH
- **WHEN** a tool response text block contains "Ignore previous instructions", "You are now", or role-switching directives
- **THEN** the finding is classified as HIGH severity with detail "tool '<name>' returned potential prompt injection"

#### Scenario: Clean response with no injection
- **WHEN** a tool response contains no injection patterns and no credential/internal data
- **THEN** the finding is classified as PASS

### Requirement: Content-based response scoring
The system SHALL compute a suspicion score (0.0-1.0) for each probe response using keyword-frequency analysis weighted by response size. Responses scoring above 0.7 SHALL trigger deeper regex analysis. Responses scoring below 0.3 SHALL be classified as PASS more aggressively.

#### Scenario: High-suspicion response
- **WHEN** a response contains multiple security-relevant keywords (access_key, token, password, secret) normalized to response size with score >0.7
- **THEN** all credential and metadata regex patterns are applied

### Requirement: Entropy analysis
The system SHALL compute Shannon entropy on response bodies. Entropy above 7.5 SHALL be classified as encrypted/compressed (benign). Entropy below 1.5 with high keyword score SHALL raise a finding.

#### Scenario: Low entropy with metadata
- **WHEN** response entropy <1.5 and metadata pattern matches
- **THEN** a HIGH finding reports "low-entropy metadata response detected"

### Requirement: Response classification
The system SHALL classify responses as metadata, error, data, or binary based on content-type header and body characteristics. Classification SHALL influence subsequent analysis path.

#### Scenario: Metadata response
- **WHEN** response body matches `(?i)(ami-id|instance-id|iam/)` and content-type is text
- **THEN** the response is classified as metadata and analyzed with cloud credential patterns

### Requirement: Timing analysis
The system SHALL record response times per probe and flag outliers. Responses more than 2 standard deviations faster than the mean SHALL be flagged as potential internal-service access.

#### Scenario: Anomalously fast response
- **WHEN** a probe response takes 10ms while the mean for that server is 200ms
- **THEN** an INFO finding reports "anomalously fast response (10ms vs 200ms mean) — possible internal service access"

### Requirement: Configurable response limit
The system SHALL support a `--max-response` flag (default 64KB) to control how much of each response body is read and analyzed. The previous 4KB limit SHALL be removed as a hardcoded constant.

#### Scenario: Custom response limit
- **WHEN** `--max-response 131072` is set
- **THEN** up to 128KB of each response body is read and analyzed

### Requirement: Dynamic probing is opt-in
The system SHALL require explicit user action to perform dynamic SSRF probing — either the `probe` subcommand or a `--probe` flag on `scan` with confirmation prompt.

#### Scenario: Static scan only
- **WHEN** user runs `mcp-audit static`
- **THEN** no network connections are made to MCP server endpoints

#### Scenario: Scan with probe confirmation
- **WHEN** user runs `mcp-audit scan`
- **THEN** static analysis runs first, then the user is prompted to confirm before dynamic probing begins

#### Scenario: Dedicated probe command
- **WHEN** user runs `mcp-audit probe`
- **THEN** dynamic probing begins immediately without confirmation (intent is explicit)

#### Scenario: Dry-run mode
- **WHEN** user runs `mcp-audit probe --dry-run`
- **THEN** the tool prints all endpoints and payloads that would be probed but makes zero network requests

### Requirement: Overall scan timeout
The system SHALL enforce an overall timeout on the dynamic probe phase computed as `(per-probe-timeout-seconds * concurrency) + 30 seconds`. If the probe phase exceeds this timeout, remaining probes SHALL be cancelled and the errgroup error SHALL be returned to the caller.

#### Scenario: Scan completes within timeout
- **WHEN** dynamic probing completes within the overall timeout
- **THEN** all probe results are collected and returned normally

#### Scenario: Scan exceeds overall timeout
- **WHEN** dynamic probing takes longer than the computed overall timeout
- **THEN** remaining probe goroutines are cancelled and a timeout error is returned alongside partial results

### Requirement: Errgroup error propagation
The system SHALL surface errgroup errors from `runDirectProbes` and `runMCPProbes` to the caller instead of debug-logging them. The `Probe()` function SHALL return the first errgroup error if one occurs.

#### Scenario: Probe group error surfaced
- **WHEN** an errgroup worker in `runMCPProbes` returns an error
- **THEN** `g.Wait()` returns that error, and `Probe()` returns it to the CLI layer

#### Scenario: Partial results with errors
- **WHEN** some probes succeed and an errgroup error occurs
- **THEN** the scan returns both the successfully collected findings and the error

### Requirement: Callback listener bind failure detection
The system SHALL report a bind failure when starting the blind SSRF callback listener. If the listener cannot bind to the specified port, an INFO finding SHALL be recorded noting that blind SSRF detection is disabled for this scan run. Probes SHALL continue without callback URLs when the listener is unavailable.

#### Scenario: Callback listener binds successfully
- **WHEN** the callback port is available
- **THEN** a local HTTP listener starts and callback URLs are injected into tool call arguments

#### Scenario: Callback listener bind failure
- **WHEN** the callback port is already in use
- **THEN** an INFO finding is recorded: "callback listener could not bind to port N — blind SSRF detection disabled for this scan"
- **AND** probing continues without callback URLs

### Requirement: Allowlist and blocklist
The system SHALL support `--allow-hosts` and `--block-hosts` flags accepting comma-separated IP ranges or CIDR notation to control probe targets.

#### Scenario: Blocklist excludes target
- **WHEN** user specifies `--block-hosts 169.254.169.254`
- **THEN** the AWS metadata endpoint is skipped during probing

#### Scenario: Allowlist restricts targets
- **WHEN** user specifies `--allow-hosts 127.0.0.1,192.168.0.0/16`
- **THEN** only loopback and 192.168.x.x addresses are probed; all other targets are skipped

### Requirement: Blind SSRF callback detection
The system SHALL start a local HTTP listener on a random loopback port during full-depth probing. The callback URL SHALL be injected into tool call arguments. When the callback receives a GET request, the system SHALL record a CRITICAL finding identifying which server and tool made the outbound connection.

#### Scenario: Callback triggered
- **WHEN** a probed server makes an HTTP GET to the callback URL
- **THEN** a CRITICAL finding reports "blind SSRF confirmed: server made outbound request to callback listener"

#### Scenario: No callback received
- **WHEN** no request arrives at the callback listener within 30s of the last probe
- **THEN** no blind SSRF finding is raised

### Requirement: Expanded cloud metadata targets
The system SHALL include Azure (`169.254.169.254` with `Metadata: true` header), DigitalOcean (`169.254.169.254`), and Oracle Cloud (`169.254.169.254`) metadata endpoints in extended and full probe depth.

#### Scenario: Azure metadata probe
- **WHEN** probe depth is extended or full
- **THEN** `http://169.254.169.254/metadata/instance?api-version=2021-02-01` is probed with `Metadata: true` header

### Requirement: HTTP method expansion
The system SHALL send POST and PUT probes to internal targets at extended and full depth in addition to GET probes.

#### Scenario: POST probe
- **WHEN** probe depth is extended or full
- **THEN** each internal target is also probed via HTTP POST with an empty JSON body

### Requirement: Header-based SSRF probes
The system SHALL inject internal targets into `X-Forwarded-Host`, `Host`, and `Referer` headers at extended and full depth.

#### Scenario: X-Forwarded-Host probe
- **WHEN** probe depth is extended or full
- **THEN** tool calls include `X-Forwarded-Host: 169.254.169.254` header variant

### Requirement: Redirect chain following
The system SHALL follow up to 5 redirects and detect internal IPs at any hop, not just the first redirect.

#### Scenario: Internal redirect at third hop
- **WHEN** a probe response chain is: 302 → external → 302 → external → 302 → 192.168.1.1
- **THEN** a HIGH finding reports "redirect chain leads to internal IP 192.168.1.1 at hop 3"

### Requirement: DNS rebinding probe
The system SHALL probe a DNS rebinding hostname that resolves to both external and internal IPs at full depth.

#### Scenario: DNS rebinding SSRF detected
- **WHEN** a server follows a redirect from the rebinding hostname to an internal IP
- **THEN** a HIGH finding reports "DNS rebinding SSRF detected"

### Requirement: Probe depth configuration
The system SHALL support `--probe-depth` with values `basic`, `extended`, and `full` controlling which probe techniques are used.

#### Scenario: Basic depth
- **WHEN** `--probe-depth basic` is set (default)
- **THEN** only current GET probes against 14 base targets are performed

### Requirement: MCP client inspection callbacks
The MCP client SHALL support optional `OnRequest` and `OnResponse` callback hooks invoked on each JSON-RPC call. These SHALL be used by proxy mode for real-time traffic inspection without modifying the client's core send/receive logic.

#### Scenario: Request callback invoked
- **WHEN** a `tools/call` is sent through a client with an `OnRequest` hook
- **THEN** the hook receives the method name, params, and is called before the request is sent

#### Scenario: Response callback invoked
- **WHEN** a `tools/list` response is received through a client with an `OnResponse` hook
- **THEN** the hook receives the method name, result, and response time after the response is parsed

