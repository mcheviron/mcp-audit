package levenshtein

import "testing"

func TestDistance(t *testing.T) {
	tests := []struct {
		a, b     string
		expected int
	}{
		{"", "", 0},
		{"mcp-server", "mcp-server", 0},

		{"a", "", 1},
		{"", "b", 1},
		{"@scope/mcp-server", "@scope/mcp-serve", 1},

		{"mcp-server-filesystem", "", 21},
		{"", "mcp-server-filesystem", 21},

		{"@scope/mcp-server-filesytem", "@scope/mcp-server-filesystem", 1},
		{"kitten", "sitting", 3},
		{"sunday", "saturday", 3},

		{"abc", "xyz", 3},
		{"foo", "bar", 3},

		{"mcp-server", "mcp-server-filesystem", 11},
		{"filesystem", "mcp-server-filesystem", 11},

		{"mcp-server", "mcp-serve", 1},
		{"mcp-server", "mcp-servr", 1},
		{"mcp-server", "mcp-sever", 1},
		{"mcp-server", "mpc-server", 2},
	}

	for _, tt := range tests {
		got := Distance(tt.a, tt.b)
		if got != tt.expected {
			t.Errorf("Distance(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.expected)
		}
	}
}
