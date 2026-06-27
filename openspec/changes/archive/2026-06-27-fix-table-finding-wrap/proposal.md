## Why

The table renderer in `writeSeverityGroup` prints the `Finding` field raw on one line. When findings contain long text (cross-server chain paths, adversarial probe details, tool descriptions), the text overflows the terminal width and wraps without indentation, breaking the column layout. Detail and Remediation fields already use word-wrapping via `writeWrapped` — the Finding field was missed. This affects all commands (static, scan, probe) since they share the same `writeTable` path.

## What Changes

- Wrap `Finding` text in `writeSeverityGroup` using the existing `writeWrapped` helper, matching how `Detail` and `Remediation` are already handled
- Indent continuation lines to align under the finding column (same column as the first line's text)

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `report-formatting`: Finding field in table output now word-wraps with proper indentation instead of relying on terminal line-wrap

## Impact

- `internal/report/format.go` — `writeSeverityGroup` function (~5 line change)
- `internal/report/format_table_test.go` — add test cases for long finding text
- All commands (static, scan, probe) — automatically fixed since they share `report.Write()`

## Non-goals

- Not changing the table layout structure (vertical vs horizontal)
- Not adding new format types
- Not changing how Detail or Remediation wrap (already correct)
