# Detectors Guide

## Overview

Detectors are the core of Secure Push. Each detector identifies a specific class of security issue.

## Detector Interface

```go
type Detector interface {
    Name() string
    Severity() Severity
    Detect(content string, filename string) ([]Finding, error)
}
```

## Built-in Detectors

| Detector | Severity | Description |
|----------|----------|-------------|
| ENV_FILE | CRITICAL | Detects committed `.env` files and `.envrc` files |
| AWS_SECRET_KEY | CRITICAL | Detects AWS secret keys |
| GENERIC_API_KEY | HIGH | Detects generic API keys |
| HARDCODED_PASSWORD | CRITICAL | Detects hardcoded passwords |
| AUTH_CREDENTIALS | CRITICAL | Detects various auth credentials (GitHub tokens, SSH keys, etc.) |
| CONFIG_FILE | HIGH | Detects config files that may contain sensitive data |

### Auth Credentials Detector

The `AUTH_CREDENTIALS` detector identifies various authentication tokens and credentials:

- **AWS Access Keys**: `AKIAIOSFODNN7EXAMPLE`
- **GitHub Tokens**: `ghp_...`, `gho_...`, `ghu_...`, `ghs_...`, `ghr_...`
- **GitLab Tokens**: `glpat-...`
- **Google API Keys**: `AIza...`
- **Slack Tokens**: `xoxb-...`, `xoxa-...`, `xoxp-...`, `xoxr-...`, `xoxs-...`
- **Discord Webhooks**: `https://discord.com/api/webhooks/...`
- **Telegram Bot Tokens**: `1234567890:...`
- **Azure Key Vault**: `-----BEGIN AZURE KEY VAULT-----`
- **Personal Access Tokens**: Various formats
- **SSH/PGP Keys**: Private key headers
- **JWT Tokens**: JSON Web Tokens
- **Bearer Tokens**: Authorization headers
- **Basic Auth**: Base64 encoded credentials

### Secrets Detector

The `SECRETS` detector identifies:

- **Passwords**: `password = '...'`, `passwd = '...'`, `pwd = '...'`
- **API Keys**: `api_key = '...'`, `apikey = '...'`
- **Tokens**: `token = '...'`, `access_token = '...'`
- **Secrets**: `secret = '...'`, `client_secret = '...'`
- **Database URLs**: `postgres://...`, `mysql://...`, `mongodb://...`, `redis://...`, `mssql://...`, `oracle://...`
- **Connection Strings**: `server = '...'`, `data source = '...'`
- **High Entropy Strings**: Base64-like strings that may be secrets
- **Webhooks**: `webhook = 'https://...'`

## Creating a Custom Detector

1. Create a new file in `internal/detectors/`
2. Implement the `Detector` interface
3. Add comprehensive tests
4. Register in `scanner.go`

## Example: Generic API Key Detector

```go
package detectors

import (
    "regexp"
    "strings"
)

type GenericAPIKeyDetector struct{}

func (d *GenericAPIKeyDetector) Name() string {
    return "GENERIC_API_KEY"
}

func (d *GenericAPIKeyDetector) Severity() Severity {
    return High
}

func (d *GenericAPIKeyDetector) Detect(content string, filename string) ([]Finding, error) {
    var findings []Finding
    
    // Pattern for common API key formats
    patterns := []string{
        `api[_-]?key\s*[:=]\s*['"][a-zA-Z0-9]{20,}['"]`,
        `apikey\s*[:=]\s*['"][a-zA-Z0-9]{20,}['"]`,
    }
    
    lines := strings.Split(content, "\n")
    for i, line := range lines {
        for _, pattern := range patterns {
            re := regexp.MustCompile(pattern)
            if re.MatchString(line) {
                findings = append(findings, Finding{
                    Rule:     d.Name(),
                    Severity: d.Severity(),
                    File:     filename,
                    Line:     i + 1,
                    Message:  "Potential API key detected",
                })
            }
        }
    }
    
    return findings, nil
}
```

## Testing Detectors

Use table-driven tests:

```go
func TestGenericAPIKeyDetector(t *testing.T) {
    tests := []struct {
        name     string
        content  string
        filename string
        want     int
    }{
        {"api key found", "api_key = 'abc123def456'", "config.go", 1},
        {"no api key", "package main", "main.go", 0},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            d := &GenericAPIKeyDetector{}
            got, err := d.Detect(tt.content, tt.filename)
            if err != nil {
                t.Fatalf("error: %v", err)
            }
            if len(got) != tt.want {
                t.Fatalf("got %d findings, want %d", len(got), tt.want)
            }
        })
    }
}
```

## Detector Best Practices

- Keep patterns specific to reduce false positives
- Test with real-world code samples
- Document the patterns used in comments
- Consider performance for large files
