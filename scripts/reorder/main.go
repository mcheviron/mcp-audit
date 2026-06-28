package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/format"
	"os"
	"strings"
)

func main() {
	write := flag.Bool("w", false, "write changes in place")
	flag.Parse()

	files := flag.Args()
	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "usage: reorder [-w] file.go [file.go ...]")
		os.Exit(2)
	}

	failed := 0
	for _, path := range files {
		if err := process(path, *write); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
			failed++
		}
	}
	if failed > 0 {
		os.Exit(1)
	}
}

type declBlock struct {
	kind     string
	exported bool
	text     string
}

func process(path string, write bool) error {
	src, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	blocks, header, err := split(src)
	if err != nil {
		return fmt.Errorf("split: %w", err)
	}

	ordered := order(blocks)
	out := assemble(header, ordered)

	if os.Getenv("REORDER_DEBUG") != "" {
		fmt.Fprintln(os.Stderr, "=== pre-gofmt ===")
		fmt.Fprintln(os.Stderr, string(out))
		fmt.Fprintln(os.Stderr, "=== end ===")
	}

	out, err = format.Source(out)
	if err != nil {
		return fmt.Errorf("gofmt: %w", err)
	}

	if bytes.Equal(src, out) {
		return nil
	}

	if write {
		return os.WriteFile(path, out, 0644)
	}
	fmt.Println(string(out))
	return nil
}

func split(src []byte) ([]declBlock, []byte, error) {
	lines := strings.Split(string(src), "\n")

	packageLine := -1
	importEnd := -1
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "//") {
			continue
		}
		if packageLine == -1 && strings.HasPrefix(t, "package ") {
			packageLine = i
			continue
		}
		if strings.HasPrefix(t, "import ") || strings.HasPrefix(t, "import(") || t == "import (" {
			if strings.HasSuffix(t, ")") {
				importEnd = i
				break
			}
			for j := i + 1; j < len(lines); j++ {
				if strings.TrimSpace(lines[j]) == ")" {
					importEnd = j
					break
				}
			}
			break
		}
		if strings.HasPrefix(t, "const ") || strings.HasPrefix(t, "var ") ||
			strings.HasPrefix(t, "type ") || strings.HasPrefix(t, "func ") {
			break
		}
	}

	if packageLine == -1 {
		return nil, nil, fmt.Errorf("no package declaration")
	}

	headerEnd := importEnd + 1
	if importEnd == -1 {
		for i := packageLine + 1; i < len(lines); i++ {
			t := strings.TrimSpace(lines[i])
			if t == "" {
				continue
			}
			if strings.HasPrefix(t, "const ") || strings.HasPrefix(t, "var ") ||
				strings.HasPrefix(t, "type ") || strings.HasPrefix(t, "func ") {
				headerEnd = i
				break
			}
		}
	}

	body := strings.Join(lines[headerEnd:], "\n")
	blocks, err := lexBlocks(body)
	if err != nil {
		return nil, nil, err
	}

	header := strings.Join(lines[:headerEnd], "\n") + "\n"
	return blocks, []byte(header), nil
}

func lexBlocks(body string) ([]declBlock, error) {
	var blocks []declBlock
	lines := strings.Split(body, "\n")
	i := 0
	for i < len(lines) {
		line := lines[i]
		t := strings.TrimSpace(line)
		if t == "" {
			i++
			continue
		}
		var directive string
		if strings.HasPrefix(t, "//go:") {
			directive = lines[i] + "\n"
			i++
			continue
		}
		var kind string
		switch {
		case strings.HasPrefix(t, "const "):
			kind = "const"
		case strings.HasPrefix(t, "var "):
			kind = "var"
		case strings.HasPrefix(t, "type "):
			kind = "type"
		case strings.HasPrefix(t, "func "):
			kind = "func"
		default:
			return nil, fmt.Errorf("unrecognized decl at line %d: %q", i+1, t)
		}
		end := findBlockEnd(lines, i)
		b := directive + strings.Join(lines[i:end], "\n")
		blocks = append(blocks, declBlock{
			kind:     kind,
			exported: kind == "func" && isFuncExported(t),
			text:     b,
		})
		i = end
	}
	return blocks, nil
}

func findBlockEnd(lines []string, start int) int {
	depth := 0
	sawOpen := false
	for i := start; i < len(lines); i++ {
		trimmed := stripLineComment(lines[i])
		for _, r := range trimmed {
			switch r {
			case '{':
				depth++
				sawOpen = true
			case '}':
				depth--
				if sawOpen && depth == 0 {
					return i + 1
				}
			}
		}
	}
	return len(lines)
}

func stripLineComment(s string) string {
	inString := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inString != 0 {
			if c == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if c == inString {
				inString = 0
			}
			continue
		}
		if c == '"' || c == '`' {
			inString = c
			continue
		}
		if c == '/' && i+1 < len(s) && s[i+1] == '/' {
			return s[:i]
		}
	}
	return s
}

func isFuncExported(t string) bool {
	idx := strings.Index(t, "func ")
	if idx < 0 {
		return false
	}
	rest := t[idx+len("func "):]
	rest = strings.TrimSpace(rest)
	if strings.HasPrefix(rest, "(") {
		end := strings.Index(rest, ")")
		if end < 0 {
			return false
		}
		rest = strings.TrimSpace(rest[end+1:])
	}
	if rest == "" {
		return false
	}
	return rest[0] >= 'A' && rest[0] <= 'Z'
}

func order(blocks []declBlock) []declBlock {
	var consts, types, pubVars, privVars, inits, pubFns, privFns []declBlock
	for _, b := range blocks {
		switch b.kind {
		case "const":
			consts = append(consts, b)
		case "type":
			types = append(types, b)
		case "var":
			if b.exported {
				pubVars = append(pubVars, b)
			} else {
				privVars = append(privVars, b)
			}
		case "func":
			if b.exported {
				pubFns = append(pubFns, b)
			} else {
				privFns = append(privFns, b)
			}
		default:
			inits = append(inits, b)
		}
	}
	out := make([]declBlock, 0, len(blocks))
	out = append(out, consts...)
	out = append(out, types...)
	out = append(out, pubVars...)
	out = append(out, privVars...)
	out = append(out, inits...)
	out = append(out, pubFns...)
	out = append(out, privFns...)
	return out
}

func assemble(header []byte, blocks []declBlock) []byte {
	var b bytes.Buffer
	b.Write(header)
	if !bytes.HasSuffix(header, []byte("\n")) {
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	for i, blk := range blocks {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(blk.text)
		if !strings.HasSuffix(blk.text, "\n") {
			b.WriteByte('\n')
		}
	}
	return b.Bytes()
}