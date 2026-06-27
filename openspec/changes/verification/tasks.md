## 1. Schema version constants

- [x] 1.1 In `internal/report/json.go`, add a `const SchemaJSON = "1"` declaration at package level
- [x] 1.2 In `internal/report/sarif.go`, add a `const SchemaSARIF = "1"` declaration at package level
- [x] 1.3 Run `just build` to verify the constants compile

## 2. Manifest builder

- [x] 2.1 Create `internal/manifest/manifest.go` with a `Build()` function that returns a struct with fields: Version, Commit, BuildDate, GoVersion, TrustListSHA256, ProbesListSHA256, SchemaJSON, SchemaSARIF. Compute SHA-256 of the embedded trust data and probes data at runtime.
- [x] 2.2 Add a `WriteJSON(w io.Writer)` method that marshals the struct with sorted keys via `json.MarshalIndent` and writes to w
- [x] 2.3 Add a `WriteText(w io.Writer)` method that prints a human-readable multi-line text manifest
- [x] 2.4 Add a `ManifestFromFile(path string) (Manifest, error)` helper for tests that loads a saved manifest from disk

## 3. Verify subcommand

- [x] 3.1 Create `cmd/mcp-audit/cmd_verify.go` with a Cobra `verifyCmd` that calls `manifest.Build()`, calls `WriteJSON(os.Stdout)` by default, and `WriteText(os.Stdout)` when `--text` is passed
- [x] 3.2 In `cmd/mcp-audit/root.go`, register `verifyCmd` with `RootCmd.AddCommand(verifyCmd)`
- [x] 3.3 Run `just build` to verify the command compiles and is registered

## 4. Tests

- [x] 4.1 Add `internal/manifest/manifest_test.go` with tests: `Build()` returns non-empty fields, `WriteJSON` produces valid JSON with all required keys, JSON output is byte-identical across two calls, SHA-256 hashes are 64 hex chars, `WriteText` output contains the version string
- [x] 4.2 Add `cmd/mcp-audit/verify_test.go` with tests: `verifyCmd` is registered on root, `--text` flag exists, `verifyCmd.Use` equals "verify"
- [x] 4.3 Run `just test-all` to verify all tests pass

## 5. Lint

- [x] 5.1 Run `just check` and fix any lint issues
