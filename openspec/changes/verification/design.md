## Context

`mcp-audit` is a single static Go binary. Its output is consumed by humans (table
view) and by automated evidence-collection systems (JSON, SARIF). Both consumers
need to know exactly which version of the binary produced a given artifact so
they can decide whether to trust findings, replay the scan, or escalate a
regression.

Currently `mcp-audit version` prints a single string built from `cmd/mcp-audit/version.go`
constants. There is no machine-readable manifest, no hash of embedded data, and
no schema version per output format. The four umbrella specs each have implicit
schemas (table columns, JSON keys, SARIF rule IDs) but they are not versioned.

## Goals / Non-Goals

**Goals:**
- Emit a deterministic JSON manifest on `mcp-audit verify`
- Manifest includes: semver version, git commit, build date, Go version, embedded
  data SHA-256 hashes (typo list, package list), and per-format schema versions
- Same binary produces byte-identical manifest (no timestamps, no randomization)
- JSON output is sorted by key for determinism
- Human-readable text output via `--text` flag

**Non-goals:**
- Not signing binaries (PKI out of scope)
- Not implementing remote attestation or telemetry
- Not versioning the table format separately (only JSON and SARIF have schemas)
- Not changing existing `version` subcommand
- Not adding `--verify-config` or any other flags to existing subcommands

## Decisions

**Decision: Use Go `runtime.Version()` and ldflags-set variables**

The Go version is obtained at runtime via `runtime.Version()`. The git commit,
build date, and semver are injected via ldflags at build time. This matches the
pattern already used in `cmd/mcp-audit/version.go`.

**Decision: SHA-256 of embedded data, not full file content**

The typo list and package list are embedded via `//go:embed`. At startup we hash
their byte slices with SHA-256 and store the hex digest in the manifest. This
catches any accidental change to embedded data without bloating the manifest.

**Decision: Schema versions as plain strings**

Each output format declares a schema version constant in its package. The verify
command imports these constants and embeds them in the manifest. Bumping a
schema is a code change that requires updating the constant.

**Decision: JSON output is sorted by key**

Use `json.Marshal` on a `map[string]any` with sorted keys, or use
`json.MarshalIndent` on a struct with explicit field order. Struct order is
preferred for type safety. We will use a struct with explicit fields so the
output order is stable across runs and Go versions.

**Decision: Print manifest to stdout, errors to stderr**

Standard CLI convention. Piping `mcp-audit verify | jq .version` works.

**Decision: Exit code 0 on success**

The verify command cannot fail at runtime (all data is embedded). Exit 0 always.

## Risks / Trade-offs

- Build pipeline must inject ldflags for git commit / build date to be useful.
  Without ldflags these will be empty strings. Mitigation: README documents the
  build flags, and the manifest includes a `build_injected` boolean indicating
  whether ldflags were used (detected by checking if version/commit are empty).

- Schema version constants must be kept in sync with output format changes. If
  a contributor changes the JSON format without bumping the schema version, the
  manifest becomes misleading. Mitigation: code review checklist item, plus the
  manifest itself can be diffed between binary versions.

- The SHA-256 hash of embedded data requires the binary to compute the hash at
  startup. For very large embedded lists this could add milliseconds. For the
  current ~600KB typo list, the hash computation is negligible (<1ms).
