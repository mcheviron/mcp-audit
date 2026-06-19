# mcp-audit Community Database

Shared intelligence for MCP ecosystem security. Compatible with [MCPShield](https://github.com/mcpshield/mcpshield) vuln database format.

## Files

| File | Description |
|------|-------------|
| `trusted.json` | Known-safe npm/pipx scopes and package names |
| `blocked.json` | Known-malicious or spoofed packages |
| `cve.json` | CVE entries in MCPShield-compatible format |

## Schema

### trusted.json / blocked.json

```json
{
  "version": "1.0.0",
  "generated_at": "2026-06-20T00:00:00Z",
  "trusted": ["@anthropic/", "@modelcontextprotocol/"],
  "blocked": ["mcp-spoofed-package"],
  "servers": {
    "my-server": {
      "trusted": ["@my-org/tools"],
      "blocked": []
    }
  },
  "tools": {},
  "pinned_tools": {
    "my-server/list_files": "sha256:abc..."
  }
}
```

### cve.json

MCPShield-compatible vulnerability format:

```json
[
  {
    "name": "MCP-2026-0001",
    "cve": "CVE-2026-00001",
    "cvss": 7.5,
    "affected_versions": ["<1.2.0"],
    "description": "SSRF in server-filesystem tool allowing internal network access",
    "package": "@modelcontextprotocol/server-filesystem",
    "published": "2026-01-15T00:00:00Z",
    "references": ["https://github.com/modelcontextprotocol/servers/security/advisories/..."],
    "remediation": "Upgrade to @modelcontextprotocol/server-filesystem@1.2.0 or later"
  }
]
```

## Contributing

1. Fork this repository
2. Add your entry to the appropriate JSON file
3. Ensure valid JSON (`just validate` or `python -m json.tool file.json`)
4. Open a PR with a clear description of the change

### Adding trusted packages

Add npm/pipx scopes or full package names to `trusted.json`:

- Scopes: `@org-name/` (trailing slash is the wildcard)
- Packages: full npm/pipx identifiers

### Reporting vulnerabilities

Add entries to `cve.json` with the CVE number, CVSS score, affected versions, and remediation steps.

### Reporting blocked packages

Add package names to `blocked.json`. Include a comment (in the PR description) explaining why the package is considered malicious.

## Releases

GitHub Actions automatically validates schema and publishes releases when `trusted.json`, `blocked.json`, or `cve.json` changes on `main`. Download the latest at:

```
https://github.com/mcp-audit-db/releases/latest/download/trust.json
```

## Local update

```bash
mcp-audit trust update
```

## Upload findings

```bash
mcp-audit upload
```
