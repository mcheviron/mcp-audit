## Context

`writeSeverityGroup` in `internal/report/format.go` renders each finding as:

```
<SEVERITY>  <server-padded>  <finding>\n
```

The `<finding>` is printed raw via `fmt.Fprintf` with no width constraint. When findings are short (static: "package not in trust lists, no typosquat detected"), this works fine. When findings are long (probe/cross-server: "potential data exfiltration chain: datagouv/search_datasets -> deepwiki/ask_question -> datagouv/get_dataservice_info"), the text exceeds terminal width and the terminal's hard-wrap places continuation lines at column 0, breaking the column layout.

Detail and Remediation fields already use `writeWrapped` from `wrap.go` for proper word-wrapping with indentation. The Finding field was simply missed in the prior rewrite.

## Goals / Non-Goals

**Goals:**
- Wrap Finding text to fit within the available content width, using the same `writeWrapped` helper already used by Detail and Remediation
- Indent continuation lines to align with the finding column

**Non-Goals:**
- Changing the output layout structure (vertical table with per-file sub-headers)
- Adding new columns or format types
- Changing how Detail or Remediation wrap (already correct)

## Decisions

**Decision: Reuse `writeWrapped` for Finding**

The existing `writeWrapped` function in `wrap.go` handles word-wrapping with configurable prefix, indent, and width. For the Finding field:
- First line: prefix is the severity+server line (`<SEVERITY>  <server-padded>  `) — no prefix needed since `writeWrapped` first line gets `prefix` prepended but here the first line IS the severity+server+start-of-finding, so we print the severity+server prefix ourselves and pass the finding text to `writeWrapped` with an empty first-line prefix and the column indent
- Continuation lines: indented to the finding column start (space past severity + 2 spaces + server + 2 spaces)

Alternative considered: Using `text/tabwriter`. Rejected — tabwriter doesn't handle line-length wrapping, it only aligns tab stops.

Alternative considered: Pre-computing wrapped lines and joining. Rejected — `writeWrapped` already exists and is tested; no reason to inline the logic.

**Decision: Finding width = same content width used for Detail/Remediation**

The content width for Detail/Remediation is `opts.Width - (2 + serverWidth + 2 + prefixLen)`. For the Finding first line, the prefix is the finding text itself (starting at the same column offset), so continuation lines use the same indent. The effective width for wrapping is `contentWidth(opts.Width, 2 + serverWidth + 2)` — same column where finding text starts.

## Risks / Trade-offs

- Finding text that contains no spaces (e.g., long URLs) won't wrap mid-word. This is consistent with how `wrapText` works (word-boundary wrapping) and same behavior as Detail/Remediation. → Acceptable; the terminal will hard-wrap long unbroken tokens as it does today.

- Very narrow terminals (<40 cols) may produce cramped output. → Already a problem for existing wrapped fields. Not making it worse. The `contentWidth` helper already clamps to minimum 20.
