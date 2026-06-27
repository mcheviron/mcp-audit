## Why

After running `mcp-audit scan`, operators need a way to confirm the binary itself
is functioning correctly and that the findings they receive are trustworthy. The
current CLI has no `verify` subcommand — there is no machine-readable fingerprint
of the binary's version, build metadata, or supported feature set. When findings
are exported as evidence and later reviewed by an auditor or downstream tool,
the recipient has no way to confirm which version of `mcp-audit` produced them.

The existing `version` subcommand prints a short string but does not expose the
schema versions, embedded data versions, or hash needed for non-repudiation.

## What Changes

- Add a new `verify` subcommand that emits a structured JSON manifest of the
  binary: version, git commit, build date, Go runtime version, embedded package
  list hash, embedded typo list hash, and the schema versions of the four output
  formats (table, JSON, SARIF).
- The manifest SHALL be deterministic — same binary produces byte-identical output.
- The manifest SHALL be printed to stdout in JSON, suitable for piping into
  `sha256sum`, `jq`, or evidence-collection systems.
- Add a `--json` flag (default true) for machine-readable output and a
  `--text` flag for human-readable output.
- The `version` subcommand remains unchanged for backward compatibility.

## Capabilities

### New Capabilities

- `binary-verification`: The `verify` subcommand emits a deterministic JSON
  manifest of the binary's identity and embedded data versions.

## Impact

- `cmd/mcp-audit/` — new `verify.go` file with the Cobra command
- `cmd/mcp-audit/main.go` (or root) — register the new command
- `internal/report/` — no changes
- `internal/scanner/` — no changes
- New test file: `cmd/mcp-audit/verify_test.go`

## Non-goals

- Not signing the binary or the manifest (would require key management)
- Not adding a remote attestation or telemetry endpoint
- Not changing the existing `version` subcommand output
- Not changing the embedded data files themselves (only exposing their hashes)
- Not adding a `--verify-config` flag (out of scope for this change)
