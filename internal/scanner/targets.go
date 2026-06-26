package scanner

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/mcheviron/mcp-audit/internal/hostutil"
)

var baseTargets = []string{
	"http://127.0.0.1/",
	"http://127.0.0.1:80/",
	"http://127.0.0.1:8080/",
	"http://127.0.0.1:3000/",
	"http://[::1]/",
	"http://0.0.0.0/",
	"http://169.254.169.254/latest/meta-data/",
	"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
	"http://169.254.169.254/latest/user-data/",
	"http://metadata.google.internal/computeMetadata/v1/",
	"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
	"http://192.168.1.1/",
	"http://10.0.0.1/",
	"http://172.16.0.1/",
}

var expandedTargets = []string{
	"http://169.254.169.254/metadata/instance?api-version=2021-02-01",
	"http://169.254.169.254/metadata/v1.json",
	"http://169.254.169.254/opc/v1/instance/",
	"http://169.254.169.254/openstack/latest/meta_data.json",
}

var dnsRebindingHost = "http://1.0.0.127.1pointeruhj4t0nk7rl9.z.okd.sx/"

func getProbeTargets(depth ProbeDepth) []string {
	if depth <= DepthBasic {
		return baseTargets
	}
	targets := make([]string, len(baseTargets), len(baseTargets)+len(expandedTargets)+1)
	copy(targets, baseTargets)
	if depth >= DepthExtended {
		targets = append(targets, expandedTargets...)
	}
	if depth >= DepthFull {
		targets = append(targets, dnsRebindingHost)
	}
	return targets
}

func filterTargets(targets, allowHosts, blockHosts []string) []string {
	if len(allowHosts) == 0 && len(blockHosts) == 0 {
		return targets
	}

	var filtered []string
	for _, t := range targets {
		if len(blockHosts) > 0 && hostMatchesAny(t, blockHosts) {
			continue
		}
		if len(allowHosts) > 0 && !hostMatchesAny(t, allowHosts) {
			continue
		}
		filtered = append(filtered, t)
	}
	return filtered
}

func hostMatchesAny(target string, hosts []string) bool {
	for _, h := range hosts {
		if hostutil.Matches(target, h) {
			return true
		}
	}
	return false
}

var probeMethods = []string{http.MethodGet, http.MethodPost, http.MethodPut}

var probeHeaders = map[string]string{
	"Metadata":         "true",
	"X-Forwarded-Host": "169.254.169.254",
	"Host":             "169.254.169.254",
	"Referer":          "http://169.254.169.254/",
}

func loadTargetsFile(path string) []string {
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		slog.Debug("load targets file", "path", path, "err", err)
		return nil
	}
	var targets []string
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}
	return targets
}

func countRedirectHops(resp *http.Response) (int, string) {
	hop := 0
	lastURL := ""
	req := resp.Request
	if req == nil {
		return 0, ""
	}
	for req != nil {
		if req.Response == nil {
			break
		}
		if req.Response.StatusCode >= 300 && req.Response.StatusCode < 400 {
			hop++
			loc := req.Response.Header.Get("Location")
			if loc != "" {
				lastURL = loc
			}
		}
		req = req.Response.Request
	}
	if hop > 0 {
		return hop, lastURL
	}
	return 0, ""
}

func isInternalHost(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return false
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast()
	}
	ips, err := net.DefaultResolver.LookupIPAddr(context.Background(), host)
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if ip.IP.IsLoopback() || ip.IP.IsPrivate() || ip.IP.IsUnspecified() || ip.IP.IsLinkLocalUnicast() {
			return true
		}
	}
	return false
}
