## ADDED Requirements

### Requirement: User-supplied trust config file
The system SHALL accept a `--trust-config <path>` flag pointing to a JSON file defining `trusted` and `blocked` package name arrays. When the flag is omitted, the system SHALL look for `~/.config/mcp-audit/trust.json`.

#### Scenario: Config file loaded successfully
- **WHEN** user runs `mcp-audit static --trust-config /path/to/trust.json` and the file contains valid JSON with `trusted` and `blocked` arrays
- **THEN** packages matching `blocked` entries are classified as CRITICAL, packages matching `trusted` entries are classified as PASS, and unknown packages are checked against the `trusted` list via Levenshtein distance

#### Scenario: Default config path
- **WHEN** user runs `mcp-audit static` without `--trust-config` and `~/.config/mcp-audit/trust.json` exists
- **THEN** that file is loaded automatically

#### Scenario: No config file present
- **WHEN** no `--trust-config` flag is given and `~/.config/mcp-audit/trust.json` does not exist
- **THEN** typosquat checks are skipped silently and each package reports PASS with finding "no trust config loaded"

#### Scenario: Explicit trust config path fails
- **WHEN** user runs `mcp-audit static --trust-config /path/to/missing.json` and the file does not exist or is malformed
- **THEN** the tool exits with code 2 and prints the error to stderr

#### Scenario: Empty config
- **WHEN** the trust config file contains `{}` or has empty `trusted`/`blocked` lists with no matching per-tool or per-server scope
- **THEN** each package reports PASS with finding "no trust rules apply for this package"

### Requirement: Per-tool and per-server trust scoping
The system SHALL support optional `tools` and `servers` maps in the trust config JSON, each keyed by tool name or server name with `trusted`/`blocked` arrays. Resolution order SHALL be: server scope > tool scope > global scope (full override, not merged).

#### Scenario: Tool-specific trust
- **WHEN** trust config has `"tools": {"claude": {"trusted": ["claude-only-pkg"]}}` and a server from tool "claude" is scanned
- **THEN** the tool-scoped trusted list is used instead of the global list

#### Scenario: Server-specific trust
- **WHEN** trust config has `"servers": {"filesystem": {"blocked": ["bad-pkg"]}}` and server "filesystem" is scanned
- **THEN** the server-scoped blocked list is used, overriding both tool and global scopes

#### Scenario: Fallback to global
- **WHEN** no server or tool scope matches the current server entry
- **THEN** the top-level `trusted` and `blocked` lists are used

### Requirement: Scanner struct for shared configuration
The system SHALL expose a `Scanner` struct holding `TrustConfig`, `Probes`, `AllowHosts`, and `BlockHosts` fields. A `NewScanner` constructor SHALL return a zero-value Scanner. `SetTrustConfig(path)` SHALL load the trust config from disk, falling back to the default path when empty.

#### Scenario: Scanner construction
- **WHEN** `NewScanner()` is called
- **THEN** a Scanner with nil TrustConfig and empty probe lists is returned

#### Scenario: SetTrustConfig with explicit path
- **WHEN** `SetTrustConfig("/path/to/config.json")` is called with a valid file
- **THEN** `Scanner.TrustConfig` is populated and nil error is returned

### Requirement: Trust config in dynamic probing
The system SHALL apply trust config filtering to the dynamic probe pipeline. Servers whose resolved scope contains any `blocked` entries SHALL be excluded from probing.

#### Scenario: Blocked server skipped in probe
- **WHEN** `mcp-audit probe --trust-config ./trust.json` is run and trust config blocks a server
- **THEN** that server is excluded from direct HTTP probes and MCP tool-call probes

#### Scenario: Trust config ignored without flag
- **WHEN** `mcp-audit probe` is run without `--trust-config` and no default trust file exists
- **THEN** all discovered HTTP servers are probed normally

## REMOVED Requirements

### Requirement: Known package databases
**Reason**: Hardcoded `known_legitimate.txt` (25 entries) and `known_malicious.txt` (13 entries) embedded at compile time via `//go:embed` do not scale. Users now supply their own trust/block lists via `--trust-config`.

**Migration**: Create `~/.config/mcp-audit/trust.json` with `trusted` and `blocked` arrays. Old embedded lists are deleted.

## MODIFIED Requirements

### Requirement: Typosquat detection threshold
The system SHALL flag any package name whose Levenshtein distance to an entry in the resolved trust scope's `trusted` list is ≤ 2 as a potential typosquat at INFO severity. The resolved scope is determined by `ScopeFor(serverName, toolName)`. If no trust config is loaded, no typosquat detection is performed.

#### Scenario: Typosquat detected
- **WHEN** a discovered server uses "mcp-server-filesytem" and "mcp-server-filesystem" is in the resolved trusted list
- **THEN** the scanner reports an INFO finding: "Package X is potential typosquat of Y (distance: 2)"

#### Scenario: Distance too large
- **WHEN** a discovered package name has Levenshtein distance 3 or greater from all trusted packages in the resolved scope
- **THEN** no typosquat alert is raised

#### Scenario: Blocked package match
- **WHEN** a discovered package matches an entry in the resolved `blocked` list
- **THEN** a CRITICAL finding is raised regardless of Levenshtein distance

#### Scenario: Trusted package match
- **WHEN** a discovered package matches an entry in the resolved `trusted` list
- **THEN** a PASS finding is reported with "known trusted package"

#### Scenario: No trust config
- **WHEN** no trust config file is present and no `--trust-config` flag is given
- **THEN** all packages receive PASS with finding "no trust config loaded"

#### Scenario: No applicable scope
- **WHEN** a trust config is loaded but the resolved scope for a server has empty trusted and blocked lists
- **THEN** the package receives PASS with finding "no trust rules apply for this package"
