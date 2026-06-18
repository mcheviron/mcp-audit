# dynamic-ssrf-probing Delta Specification

## ADDED Requirements

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
