package completion

import (
	"fmt"
	"io"
	"os"
	"strings"
)

type flagInfo struct {
	name     string
	help     string
	vals     string
	pathKind byte
}

const (
	pathNone byte = iota
	pathFile
	pathDir
)

var knownFlags = []flagInfo{
	{"--format", "Output format", "table json sarif junit", pathNone},
	{"--dry-run", "Print what would be probed without making requests", "", pathNone},
	{"--targets", "Comma-separated probe target URLs", "", pathNone},
	{"--allow-hosts", "Comma-separated hosts/IPs to allow", "", pathNone},
	{"--block-hosts", "Comma-separated hosts/IPs to block", "", pathNone},
	{"--probe-depth", "Probe depth", "basic extended full", pathNone},
	{"--callback-port", "Callback listener port", "", pathNone},
	{"--targets-file", "File with probe targets", "", pathFile},
	{"--max-response", "Max response body size in bytes", "", pathNone},
	{"--trust-config", "Path to trust config JSON", "", pathFile},
	{"--transport", "Force transport type", "stdio sse http", pathNone},
	{"--auth-token", "Bearer token for MCP auth", "", pathNone},
	{"--auth-headers", "Comma-separated key=value auth headers", "", pathNone},
	{"--tls-cert", "TLS client cert file", "", pathFile},
	{"--tls-key", "TLS client key file", "", pathFile},
	{"--no-tool-analysis", "Disable tool description analysis", "", pathNone},
	{"--snapshot-dir", "Override snapshot directory", "", pathDir},
	{"--no-snapshot", "Disable snapshot persistence", "", pathNone},
	{"--no-trust-on-first-use", "Require pre-populated pinned hashes", "", pathNone},
	{"--no-secret-scan", "Disable credential scanning", "", pathNone},
	{"--verbose", "Enable debug logging (DEBUG level)", "", pathNone},
	{"--quiet", "Suppress info logs (WARN level and above)", "", pathNone},
	{"--debug", "Include source file location in log lines", "", pathNone},
	{"--severity-min", "Minimum severity to display", "PASS INFO LOW MEDIUM HIGH CRITICAL", pathNone},
	{"--output-file", "Write report to file", "", pathFile},
	{"--timeout", "Timeout in seconds for MCP handshake", "", pathNone},
	{"--concurrency", "Maximum concurrent probes", "", pathNone},
	{"--no-color", "Disable terminal color codes", "", pathNone},
}

func allFlagNames() string {
	var names []string
	for _, f := range knownFlags {
		names = append(names, f.name)
	}
	return strings.Join(names, " ")
}

func Generate(shell string, w io.Writer) error {
	switch shell {
	case "bash":
		return genBash(w)
	case "zsh":
		return genZsh(w)
	case "fish":
		return genFish(w)
	default:
		fmt.Fprintf(os.Stderr, "mcp-audit completion: unknown shell %q (use bash, zsh, or fish)\n", shell)
		return fmt.Errorf("unknown shell: %s", shell)
	}
}

func genBash(w io.Writer) error {
	var cases strings.Builder
	for _, f := range knownFlags {
		if f.vals != "" {
			fmt.Fprintf(&cases,
				"\t\t%s)\n\t\t\tCOMPREPLY=( $(compgen -W %q -- \"$cur\") )\n\t\t\treturn\n\t\t\t;;\n",
				f.name, f.vals)
		}
	}
	_, err := fmt.Fprintf(w, `# bash completion for mcp-audit
_mcp_audit_completion() {
	local cur prev words cword
	_init_completion || return
	case $prev in
		mcp-audit)
			COMPREPLY=( $(compgen -W "scan static probe version completion help" -- "$cur") )
			return
			;;
%s
	esac
	if [[ "$cur" == -* ]]; then
		COMPREPLY=( $(compgen -W %q -- "$cur") )
	fi
}
complete -F _mcp_audit_completion mcp-audit
`, cases.String(), allFlagNames())
	return err
}

func genZsh(w io.Writer) error {
	var b strings.Builder
	b.WriteString("#compdef mcp-audit\n\nlocal -a subcmds\nsubcmds=(scan static probe version completion help)\n\n")
	for _, f := range knownFlags {
		if f.vals != "" {
			fmt.Fprintf(&b, "local -a %s_vals\n%s_vals=(%s)\n", f.name[2:], f.name[2:], f.vals)
		}
	}
	b.WriteString("\n_arguments -C \\\n\t'1: :{_describe \"subcommand\" subcmds}'")

	for _, f := range knownFlags {
		switch {
		case f.vals != "":
			fmt.Fprintf(&b, " \\\n\t'*%s[{_describe \"%s\" %s_vals}]:%s: '", f.name, f.help, f.name[2:], f.help)
		case f.pathKind == pathFile:
			fmt.Fprintf(&b, " \\\n\t'*%s=-[%s]:%s:_files'", f.name, f.help, f.help)
		case f.pathKind == pathDir:
			fmt.Fprintf(&b, " \\\n\t'*%s=-[%s]:%s:_directories'", f.name, f.help, f.help)
		case f.name == "--targets" || f.name == "--allow-hosts" || f.name == "--block-hosts" ||
			f.name == "--auth-headers" || f.name == "--auth-token" || f.name == "--max-response" ||
			f.name == "--callback-port" || f.name == "--timeout" || f.name == "--concurrency":
			fmt.Fprintf(&b, " \\\n\t'*%s=-[%s]:%s: '", f.name, f.help, f.help)
		default:
			fmt.Fprintf(&b, " \\\n\t'*%s[%s]'", f.name, f.help)
		}
	}
	b.WriteString("\n")
	_, err := fmt.Fprint(w, b.String())
	return err
}

func genFish(w io.Writer) error {
	var b strings.Builder
	b.WriteString("# fish completion for mcp-audit\n\ncomplete -c mcp-audit -f\n\n")
	b.WriteString(
		"complete -c mcp-audit -n \"__fish_is_first_token\" -a \"scan static probe version completion help\"\n\n")
	for _, f := range knownFlags {
		switch {
		case f.vals != "":
			fmt.Fprintf(&b, "complete -c mcp-audit -l %s -d %q -x -a %q\n", f.name[2:], f.help, f.vals)
		case f.pathKind == pathFile || f.pathKind == pathDir:
			fmt.Fprintf(&b, "complete -c mcp-audit -l %s -d %q -r\n", f.name[2:], f.help)
		default:
			fmt.Fprintf(&b, "complete -c mcp-audit -l %s -d %q\n", f.name[2:], f.help)
		}
	}
	_, err := fmt.Fprint(w, b.String())
	return err
}
