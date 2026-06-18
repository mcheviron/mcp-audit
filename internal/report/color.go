package report

import (
	"os"

	"golang.org/x/term"
)

func useColor() bool {
	return term.IsTerminal(int(os.Stdout.Fd())) && os.Getenv("NO_COLOR") == ""
}

func colorize(level string) string {
	if !useColor() {
		return level
	}
	switch level {
	case "CRITICAL":
		return "\033[31m" + level + "\033[0m"
	case "HIGH":
		return "\033[33m" + level + "\033[0m"
	case "MEDIUM":
		return "\033[36m" + level + "\033[0m"
	case "LOW":
		return "\033[34m" + level + "\033[0m"
	case "INFO":
		return "\033[2m" + level + "\033[0m"
	case "PASS":
		return "\033[32m" + level + "\033[0m"
	default:
		return level
	}
}
