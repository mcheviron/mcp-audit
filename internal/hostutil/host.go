package hostutil

import (
	"net/url"
	"strings"
)

func Matches(target, pattern string) bool {
	host := extractHost(target)
	if host == "" {
		return false
	}
	if strings.EqualFold(host, pattern) {
		return true
	}
	return strings.HasSuffix(host, "."+pattern)
}

func extractHost(target string) string {
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil && u.Host != "" {
			return u.Hostname()
		}
	}
	if i := strings.Index(target, "/"); i >= 0 {
		target = target[:i]
	}
	if i := strings.Index(target, ":"); i >= 0 {
		target = target[:i]
	}
	return strings.TrimSpace(target)
}
