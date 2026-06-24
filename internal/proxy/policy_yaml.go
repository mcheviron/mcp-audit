package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
)

type yamlNode struct {
	scalar   string
	mapping  map[string]*yamlNode
	sequence []*yamlNode
	kind     int
}

const (
	yamlScalar  = 0
	yamlMapping = 1
	yamlSeq     = 2
)

func parsePolicyYAML(data []byte) (*PolicyConfig, error) {
	node, err := parseYAML(data)
	if err != nil {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}

	jsonData, err := yamlNodeToJSON(node)
	if err != nil {
		return nil, fmt.Errorf("convert to JSON: %w", err)
	}

	var cfg PolicyConfig
	if err := json.Unmarshal(jsonData, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal policy: %w", err)
	}
	return &cfg, nil
}

func parseYAML(data []byte) (*yamlNode, error) {
	lines := strings.Split(string(data), "\n")
	var cleaned []string
	for _, line := range lines {
		if before, _, ok := strings.Cut(line, "#"); ok {
			cleaned = append(cleaned, before)
		} else {
			cleaned = append(cleaned, line)
		}
	}

	node, _, err := parseNodes(cleaned, 0, -1)
	if err != nil {
		return nil, err
	}
	return node, nil
}

type yamlLine struct {
	indent int
	text   string
	index  int
}

func buildLineInfo(lines []string) []yamlLine {
	var info []yamlLine
	for i, line := range lines {
		trimmed := strings.TrimLeft(line, " \t")
		if trimmed == "" {
			continue
		}
		indent := len(line) - len(trimmed)
		info = append(info, yamlLine{indent: indent, text: trimmed, index: i})
	}
	return info
}

func parseNodes(lines []string, start, parentIndent int) (*yamlNode, int, error) {
	info := buildLineInfo(lines[start:])
	if len(info) == 0 {
		return &yamlNode{kind: yamlScalar, scalar: "null"}, start, nil
	}

	if info[0].text[0] == '-' {
		return parseSequenceNodes(lines, start, parentIndent)
	}

	return parseMappingNodes(lines, start, parentIndent)
}

func parseMappingNodes(lines []string, start, parentIndent int) (*yamlNode, int, error) {
	info := buildLineInfo(lines[start:])
	if len(info) == 0 {
		return &yamlNode{kind: yamlMapping}, start, nil
	}

	node := &yamlNode{kind: yamlMapping, mapping: make(map[string]*yamlNode)}
	baseIndent := info[0].indent
	i := 0

	for i < len(info) {
		if info[i].indent < baseIndent && parentIndent >= 0 {
			break
		}
		if info[i].indent != baseIndent {
			break
		}

		line := info[i].text
		key, rest, found := strings.Cut(line, ":")
		if !found {
			i++
			continue
		}

		key = strings.TrimSpace(key)
		rest = strings.TrimSpace(rest)

		switch rest {
		case "":
			subNode, endIdx, err := parseNodes(lines, start+info[i].index+1, baseIndent)
			if err != nil {
				return nil, start, err
			}
			node.mapping[key] = subNode
			entryLine := info[i].index
			i = 0
			for idx, li := range info {
				if li.index >= endIdx || (li.index > entryLine && li.indent <= baseIndent) {
					i = idx
					break
				}
			}
			if i == 0 {
				i = len(info)
			}
		case "[]":
			node.mapping[key] = &yamlNode{kind: yamlSeq}
			i++
		case "{}":
			node.mapping[key] = &yamlNode{kind: yamlMapping}
			i++
		default:
			node.mapping[key] = &yamlNode{kind: yamlScalar, scalar: rest}
			i++
		}
	}

	endLine := start
	if i > 0 && i-1 < len(info) {
		endLine = start + info[i-1].index - info[0].index + 1
	}
	return node, endLine, nil
}

func parseSequenceNodes(lines []string, start, parentIndent int) (*yamlNode, int, error) {
	info := buildLineInfo(lines[start:])
	if len(info) == 0 {
		return &yamlNode{kind: yamlSeq}, start, nil
	}

	node := &yamlNode{kind: yamlSeq}
	baseIndent := info[0].indent
	i := 0

	for i < len(info) {
		if info[i].indent < baseIndent && parentIndent >= 0 {
			break
		}
		if info[i].indent != baseIndent {
			break
		}
		if len(info[i].text) == 0 || info[i].text[0] != '-' {
			break
		}

		// Find the end of this sequence item (next - at same indent or lower)
		itemEnd := len(lines)
		for j := i + 1; j < len(info); j++ {
			if info[j].indent <= baseIndent {
				itemEnd = info[j].index
				break
			}
		}

		rest := strings.TrimSpace(info[i].text[1:])

		switch {
		case rest == "":
			if i+1 < len(info) && info[i+1].indent > baseIndent {
				subNode, _, err := parseNodes(lines, start+info[i+1].index, baseIndent)
				if err != nil {
					return nil, start, err
				}
				node.sequence = append(node.sequence, subNode)
			} else {
				node.sequence = append(node.sequence, &yamlNode{kind: yamlScalar, scalar: "null"})
			}
		case strings.Contains(rest, ":"):
			var mappingLines []string
			mappingLines = append(mappingLines, rest)
			for j := i + 1; j < len(info) && info[j].index < itemEnd; j++ {
				relIndent := info[j].indent - (baseIndent + 2)
				relIndent = max(relIndent, 0)
				mappingLines = append(mappingLines, strings.Repeat(" ", relIndent)+info[j].text)
			}
			mappingNode, _, err := parseMappingNodes(mappingLines, 0, 0)
			if err != nil {
				return nil, start, err
			}
			node.sequence = append(node.sequence, mappingNode)
		default:
			node.sequence = append(node.sequence, &yamlNode{kind: yamlScalar, scalar: rest})
		}

		// Advance to next sequence item
		i++
		for i < len(info) && info[i].index < itemEnd {
			i++
		}
	}

	endLine := start + info[min(i, len(info)-1)].index - info[0].index + 1
	return node, endLine, nil
}

func yamlNodeToJSON(node *yamlNode) ([]byte, error) {
	switch node.kind {
	case yamlScalar:
		return convertScalar(node.scalar)
	case yamlMapping:
		return convertMapping(node.mapping)
	case yamlSeq:
		return convertSequence(node.sequence)
	default:
		return []byte("null"), nil
	}
}

func convertScalar(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "null" || s == "~" {
		return []byte("null"), nil
	}
	if s == "true" || s == "True" || s == "TRUE" {
		return []byte("true"), nil
	}
	if s == "false" || s == "False" || s == "FALSE" {
		return []byte("false"), nil
	}
	if _, err := strconv.ParseInt(s, 10, 64); err == nil {
		return []byte(s), nil
	}
	if _, err := strconv.ParseFloat(s, 64); err == nil {
		return []byte(s), nil
	}
	unquoted := s
	if strings.HasPrefix(s, "\"") && strings.HasSuffix(s, "\"") {
		inner := s[1 : len(s)-1]
		var buf strings.Builder
		buf.Grow(len(inner))
		for i := 0; i < len(inner); i++ {
			if inner[i] == '\\' && i+1 < len(inner) {
				i++
				switch inner[i] {
				case '\\':
					buf.WriteByte('\\')
				case '"':
					buf.WriteByte('"')
				case 'n':
					buf.WriteByte('\n')
				case 'r':
					buf.WriteByte('\r')
				case 't':
					buf.WriteByte('\t')
				default:
					buf.WriteByte('\\')
					buf.WriteByte(inner[i])
				}
			} else {
				buf.WriteByte(inner[i])
			}
		}
		unquoted = buf.String()
	} else if strings.HasPrefix(s, "'") && strings.HasSuffix(s, "'") {
		unquoted = s[1 : len(s)-1]
	}
	escaped := strings.NewReplacer(
		"\\", "\\\\",
		"\"", "\\\"",
		"\n", "\\n",
		"\r", "\\r",
		"\t", "\\t",
	).Replace(unquoted)
	return []byte(`"` + escaped + `"`), nil
}

func convertMapping(m map[string]*yamlNode) ([]byte, error) {
	if len(m) == 0 {
		return []byte("{}"), nil
	}
	var buf bytes.Buffer
	buf.WriteByte('{')
	first := true
	keys := slices.Sorted(maps.Keys(m))
	for _, k := range keys {
		if !first {
			buf.WriteByte(',')
		}
		first = false
		buf.WriteByte('"')
		buf.WriteString(strings.NewReplacer(
			"\\", "\\\\",
			"\"", "\\\"",
		).Replace(k))
		buf.WriteString("\":")
		valBytes, err := yamlNodeToJSON(m[k])
		if err != nil {
			return nil, err
		}
		buf.Write(valBytes)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func convertSequence(seq []*yamlNode) ([]byte, error) {
	if len(seq) == 0 {
		return []byte("[]"), nil
	}
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, item := range seq {
		if i > 0 {
			buf.WriteByte(',')
		}
		valBytes, err := yamlNodeToJSON(item)
		if err != nil {
			return nil, err
		}
		buf.Write(valBytes)
	}
	buf.WriteByte(']')
	return buf.Bytes(), nil
}
