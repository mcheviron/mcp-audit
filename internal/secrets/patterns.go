package secrets

import "regexp"

type Pattern struct {
	Name string
	Type string
	Re   *regexp.Regexp
}

var Patterns = []Pattern{
	{Name: "aws", Type: "AWS access key", Re: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{Name: "gcp", Type: "GCP access token", Re: regexp.MustCompile(`ya29\.[0-9A-Za-z_-]{20,}`)},
	{Name: "openai", Type: "OpenAI API key", Re: regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`)},
	{Name: "github-pat", Type: "GitHub token", Re: regexp.MustCompile(`ghp_[0-9A-Za-z]{36,}`)},
	{Name: "github-oauth", Type: "GitHub token", Re: regexp.MustCompile(`gho_[0-9A-Za-z]{36,}`)},
	{Name: "github-user", Type: "GitHub token", Re: regexp.MustCompile(`ghu_[0-9A-Za-z]{36,}`)},
	{Name: "github-server", Type: "GitHub token", Re: regexp.MustCompile(`ghs_[0-9A-Za-z]{36,}`)},
	{Name: "github-refresh", Type: "GitHub token", Re: regexp.MustCompile(`ghr_[0-9A-Za-z]{36,}`)},
	{Name: "gitlab", Type: "GitLab token", Re: regexp.MustCompile(`glpat-[0-9A-Za-z_-]{20,}`)},
	{Name: "slack-bot", Type: "Slack token", Re: regexp.MustCompile(`xoxb-[0-9A-Za-z-]{20,}`)},
	{Name: "slack-user", Type: "Slack token", Re: regexp.MustCompile(`xoxp-[0-9A-Za-z-]{20,}`)},
	{Name: "slack-app", Type: "Slack token", Re: regexp.MustCompile(`xoxa-[0-9A-Za-z-]{20,}`)},
	{Name: "jwt", Type: "JWT token",
		Re: regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
	{Name: "pem", Type: "private key",
		Re: regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`)},
	{Name: "dburl", Type: "database connection string with credentials",
		Re: regexp.MustCompile(`(?i)(postgres|mysql|mongodb(\+srv)?|redis)://[^:\s"']+:[^@\s"']+@`)},
	{Name: "apikey", Type: "API key",
		Re: regexp.MustCompile(`(?i)"([^"]*api[_-]?key|[^"]*secret|[^"]*token|[^"]*password)"\s*:\s*"[^"]{20,}"`)},
}
