package secrets

import (
	"fmt"
	"strings"

	"github.com/hashicorp/go-set"
)

type Finding struct {
	Type     string
	Location string
}

func ScanRaw(data []byte, location string) []Finding {
	var findings []Finding
	seen := set.New[string](0)
	for _, p := range Patterns {
		if p.Name == "apikey" {
			matched := false
			for _, m := range p.Re.FindAllStringSubmatch(string(data), -1) {
				if len(m) < 3 {
					continue
				}
				if looksLikeEnvVarRef(m[2]) {
					continue
				}
				matched = true
				break
			}
			if !matched {
				continue
			}
			key := p.Type + "|" + location
			if seen.Contains(key) {
				continue
			}
			seen.Insert(key)
			findings = append(findings, Finding{Type: p.Type, Location: location})
			continue
		}
		if !p.Re.Match(data) {
			continue
		}
		key := p.Type + "|" + location
		if seen.Contains(key) {
			continue
		}
		seen.Insert(key)
		findings = append(findings, Finding{Type: p.Type, Location: location})
	}
	return findings
}

func ScanEnv(env map[string]string, serverName string) []Finding {
	return scanMap(env, "env var", serverName)
}

func ScanHeaders(headers map[string]string, serverName string) []Finding {
	return scanMap(headers, "header", serverName)
}

func ScanArgs(args []string, serverName string) []Finding {
	if len(args) == 0 {
		return nil
	}
	location := fmt.Sprintf("args for server %s", serverName)
	var findings []Finding
	for _, f := range scanString(strings.Join(args, " ")) {
		findings = append(findings, Finding{Type: f.Type, Location: location})
	}
	return findings
}

func scanMap(m map[string]string, label, serverName string) []Finding {
	if len(m) == 0 {
		return nil
	}
	var findings []Finding
	for key, val := range m {
		location := fmt.Sprintf("%s %s for server %s", label, key, serverName)
		for _, f := range scanString(val) {
			findings = append(findings, Finding{Type: f.Type, Location: location})
		}
	}
	return findings
}

func scanString(s string) []Finding {
	var findings []Finding
	seen := set.New[string](0)
	for _, p := range Patterns {
		if p.Name == "apikey" {
			matched := false
			for _, m := range p.Re.FindAllStringSubmatch(s, -1) {
				if len(m) < 3 {
					continue
				}
				if looksLikeEnvVarRef(m[2]) {
					continue
				}
				matched = true
				break
			}
			if !matched {
				continue
			}
			if seen.Contains(p.Type) {
				continue
			}
			seen.Insert(p.Type)
			findings = append(findings, Finding{Type: p.Type})
			continue
		}
		if !p.Re.MatchString(s) {
			continue
		}
		if seen.Contains(p.Type) {
			continue
		}
		seen.Insert(p.Type)
		findings = append(findings, Finding{Type: p.Type})
	}
	return findings
}

func looksLikeEnvVarRef(v string) bool {
	if strings.HasPrefix(v, "$") {
		return true
	}
	if strings.HasPrefix(v, "process.env.") {
		return true
	}
	return false
}
