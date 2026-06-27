## 1. Implement finding text wrapping

- [x] 1.1 In `internal/report/format.go`, replace the single `fmt.Fprintf` for finding text in `writeSeverityGroup` with a call to `writeWrapped` that uses the same content width and indent as Detail/Remediation. The first line still gets severity+server prefix; continuation lines are indented to the finding column.
- [x] 1.2 Run `just check` to verify no lint issues

## 2. Tests

- [x] 2.1 Add test cases to `internal/report/format_table_test.go` for long finding text that wraps, short finding text that stays on one line, and finding text exactly at width boundary
- [x] 2.2 Run `go test ./internal/report/...` to verify all tests pass
- [x] 2.3 Run `just test-all` to verify no regression across the full suite
