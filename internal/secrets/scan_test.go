package secrets

import (
	"strings"
	"testing"
)

func TestScanRawEachPattern(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"aws", `{"k":"AKIAIOSFODNN7EXAMPLE"}`, "AWS access key"},
		{"gcp", `ya29.a0ARrdaM` + strings.Repeat("x", 20), "GCP access token"},
		{"openai", "sk-" + strings.Repeat("a", 20), "OpenAI API key"},
		{"github-pat", "ghp_" + strings.Repeat("a", 36), "GitHub token"},
		{"github-oauth", "gho_" + strings.Repeat("a", 36), "GitHub token"},
		{"github-user", "ghu_" + strings.Repeat("a", 36), "GitHub token"},
		{"github-server", "ghs_" + strings.Repeat("a", 36), "GitHub token"},
		{"github-refresh", "ghr_" + strings.Repeat("a", 36), "GitHub token"},
		{"gitlab", "glpat-" + strings.Repeat("a", 20), "GitLab token"},
		{"slack-bot", "xoxb-" + strings.Repeat("a", 20), "Slack token"},
		{"slack-user", "xoxp-" + strings.Repeat("a", 20), "Slack token"},
		{"slack-app", "xoxa-" + strings.Repeat("a", 20), "Slack token"},
		{"jwt", "eyJ" + strings.Repeat("a", 12) + ".eyJ" + strings.Repeat("a", 12) + "." + strings.Repeat("a", 12), "JWT token"},
		{"pem", "-----BEGIN RSA PRIVATE KEY-----", "private key"},
		{"dburl", "postgres://user:pass@localhost/db", "database connection string with credentials"},
		{"mongo-srv", "mongodb+srv://admin:secretpass@cluster.abc12.mongodb.net/", "database connection string with credentials"},
		{"apikey", `{"api_key":"` + strings.Repeat("a", 20) + `"}`, "API key"},
		{"es-apikey", `{"ES_API_KEY":"` + strings.Repeat("a", 20) + `"}`, "API key"},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			findings := ScanRaw([]byte(tt.input), "config.json")
			if !findingsContain(findings, tt.want) {
				t.Fatalf("expected %q in %v", tt.want, findings)
			}
		})
	}
}

func TestScanRawNegativeCases(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"short-aws", "AKIA1234"},
		{"short-openai", "sk-short"},
		{"short-github", "ghp_short"},
		{"dburl-no-creds", "postgres://localhost/db"},
		{"mongo-srv-no-creds", "mongodb+srv://cluster.abc12.mongodb.net/"},
		{"plain", `{"command":"npx","args":["-y","pkg"]}`},
		{"env-shell", `{"CLICKHOUSE_PASSWORD":"$CLICKHOUSE_PASSWORD_DEV"}`},
		{"env-brace", `{"CLICKHOUSE_PASSWORD":"${CLICKHOUSE_PASSWORD_DEV}"}`},
		{"env-vscode", `{"BRAVE_API_KEY":"${env:BRAVE_API_KEY}"}`},
		{"env-node", `{"MY_TOKEN":"process.env.MY_TOKEN_LITERAL_X"}`},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if findings := ScanRaw([]byte(tt.input), "config.json"); len(findings) != 0 {
				t.Fatalf("expected no findings for %q, got %v", tt.name, findings)
			}
		})
	}
}

func TestScanRawEnvVarPrefixExclusion(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"real-openai", `{"api_key":"sk-` + strings.Repeat("a", 24) + `"}`, "API key"},
		{"real-password-literal", `{"password":"` + strings.Repeat("a", 30) + `"}`, "API key"},
		{"real-uppercase-key", `{"API_KEY":"sk-` + strings.Repeat("a", 24) + `"}`, "API key"},
		{"real-secret", `{"client_secret":"` + strings.Repeat("a", 30) + `"}`, "API key"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			findings := ScanRaw([]byte(tt.input), "config.json")
			if !findingsContain(findings, tt.want) {
				t.Fatalf("expected %q in %v", tt.want, findings)
			}
		})
	}
}

func TestScanEnvDetectsAndClean(t *testing.T) {
	env := map[string]string{
		"API_KEY":  "sk-" + strings.Repeat("a", 20),
		"NODE_ENV": "production",
	}
	findings := ScanEnv(env, "myserver")
	if !findingsContain(findings, "OpenAI API key") {
		t.Fatalf("expected OpenAI finding, got %v", findings)
	}
	for _, f := range findings {
		if !strings.Contains(f.Location, "env var API_KEY for server myserver") {
			t.Errorf("unexpected location: %s", f.Location)
		}
	}

	clean := ScanEnv(map[string]string{"NODE_ENV": "production"}, "myserver")
	if len(clean) != 0 {
		t.Fatalf("expected no findings for clean env, got %v", clean)
	}
}

func TestScanArgsDetectsDBURL(t *testing.T) {
	args := []string{"--db", "postgres://user:pass@localhost/db"}
	findings := ScanArgs(args, "myserver")
	if !findingsContain(findings, "database connection string with credentials") {
		t.Fatalf("expected db url finding, got %v", findings)
	}

	mongoArgs := []string{"--connectionString", "mongodb+srv://admin:secretpass@cluster.abc12.mongodb.net/"}
	mongoFindings := ScanArgs(mongoArgs, "myserver")
	if !findingsContain(mongoFindings, "database connection string with credentials") {
		t.Fatalf("expected mongodb+srv finding, got %v", mongoFindings)
	}

	if len(ScanArgs([]string{"--port", "8080"}, "myserver")) != 0 {
		t.Fatal("expected no findings for plain args")
	}
}

func TestScanHeadersDetectsBearer(t *testing.T) {
	headers := map[string]string{
		"Authorization": "Bearer ya29." + strings.Repeat("a", 20),
		"Accept":        "application/json",
	}
	findings := ScanHeaders(headers, "myserver")
	if !findingsContain(findings, "GCP access token") {
		t.Fatalf("expected GCP finding, got %v", findings)
	}
	if len(ScanHeaders(map[string]string{"Accept": "application/json"}, "myserver")) != 0 {
		t.Fatal("expected no findings for clean headers")
	}
}

func TestScanRawRedactsValue(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLE"
	findings := ScanRaw([]byte(secret), "config.json")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	for _, f := range findings {
		if strings.Contains(f.Type, secret) || strings.Contains(f.Location, secret) {
			t.Fatalf("raw secret leaked into finding: %+v", f)
		}
	}
}

func TestPatternCount(t *testing.T) {
	if len(Patterns) != 16 {
		t.Fatalf("expected 16 credential patterns, got %d", len(Patterns))
	}
}

func findingsContain(findings []Finding, want string) bool {
	for _, f := range findings {
		if f.Type == want {
			return true
		}
	}
	return false
}
