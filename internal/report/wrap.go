package report

import (
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

type TableOptions struct {
	ShowPassRemediation bool
	Width               int
}

func TerminalWidth() int {
	w, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || w <= 0 {
		return 100
	}
	return w
}

func contentWidth(total, indentLen int) int {
	if total <= 0 {
		total = 100
	}
	w := total - indentLen
	return max(w, 20)
}

func wrapText(s string, width int) []string {
	if width <= 0 || len(s) <= width {
		return []string{s}
	}
	var out []string
	for paragraph := range strings.SplitSeq(s, "\n") {
		if paragraph == "" {
			out = append(out, "")
			continue
		}
		words := strings.Fields(paragraph)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		line := words[0]
		for _, w := range words[1:] {
			if len(line)+1+len(w) > width {
				out = append(out, line)
				line = w
				continue
			}
			line += " " + w
		}
		out = append(out, line)
	}
	return out
}

func writeWrapped(w io.Writer, prefix, indent, text string, width int) error {
	if width < 20 {
		width = 20
	}
	lines := wrapText(text, width)
	for i, line := range lines {
		cell := line
		if i == 0 && prefix != "" {
			cell = prefix + " " + line
		}
		if _, err := fmt.Fprintf(w, "%s%s\n", indent, cell); err != nil {
			return err
		}
	}
	return nil
}
