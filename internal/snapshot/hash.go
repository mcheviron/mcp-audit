package snapshot

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
)

func SchemaPropertyKeys(schema map[string]any) []string {
	props, _ := schema["properties"].(map[string]any)
	if props == nil {
		return nil
	}
	return slices.Sorted(maps.Keys(props))
}

func HashToolSchema(schema map[string]any) string {
	data := normalizeJSON(schema)
	hash := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", hash)
}

func normalizeJSON(v any) []byte {
	switch val := v.(type) {
	case map[string]any:
		keys := slices.Sorted(maps.Keys(val))

		var sb strings.Builder
		sb.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			sb.Write(kb)
			sb.WriteByte(':')
			sb.Write(normalizeJSON(val[k]))
		}
		sb.WriteByte('}')
		return []byte(sb.String())

	case []any:
		var sb strings.Builder
		sb.WriteByte('[')
		for i, item := range val {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.Write(normalizeJSON(item))
		}
		sb.WriteByte(']')
		return []byte(sb.String())

	case string:
		b, _ := json.Marshal(val)
		return b

	case float64:
		b, _ := json.Marshal(val)
		return b

	case bool:
		if val {
			return []byte("true")
		}
		return []byte("false")

	case nil:
		return []byte("null")

	default:
		b, _ := json.Marshal(val)
		return b
	}
}
