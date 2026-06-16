## ADDED Requirements

### Requirement: Configurable probe target list
The system SHALL accept a `--targets` flag that overrides the default 14 probe targets with a user-supplied comma-separated list of URLs.

#### Scenario: Custom probe targets
- **WHEN** `mcp-audit probe --targets http://127.0.0.1:3000/,http://192.168.1.1/` is run
- **THEN** only the two specified targets are probed

#### Scenario: Default targets preserved
- **WHEN** `mcp-audit probe` is run without `--targets`
- **THEN** the built-in 14 internal/metadata targets are used

## MODIFIED Requirements

### Requirement: Allowlist and blocklist
The system SHALL support `--allow-hosts` and `--block-hosts` flags accepting comma-separated IP addresses, hostnames, or CIDR notation to control which probe targets are used.

#### Scenario: Blocklist excludes target
- **WHEN** user specifies `--block-hosts 169.254.169.254`
- **THEN** the AWS metadata endpoint is skipped during probing

#### Scenario: Allowlist restricts targets
- **WHEN** user specifies `--allow-hosts 127.0.0.1,192.168.0.0/16`
- **THEN** only loopback and 192.168.x.x addresses are probed; all other targets are skipped

#### Scenario: Allowlist and blocklist together
- **WHEN** user specifies `--allow-hosts 127.0.0.1,169.254.169.254 --block-hosts 169.254.169.254`
- **THEN** blocklist takes precedence and 169.254.169.254 is excluded

#### Scenario: Neither flag specified
- **WHEN** neither `--allow-hosts` nor `--block-hosts` is passed
- **THEN** all default (or `--targets`-supplied) targets are probed without filtering
