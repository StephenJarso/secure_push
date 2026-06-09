package detectors

import (
	"regexp"
	"strings"
)

type SecretsDetector struct{}

func (d *SecretsDetector) Name() string {
	return "SECRETS"
}

func (d *SecretsDetector) Severity() Severity {
	return Critical
}

var (
	passwordPattern = regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*['"]?([^\s'"]{8,})['"]?`)
	apiKeyPattern   = regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{20,})['"]?`)
	tokenPattern    = regexp.MustCompile(`(?i)(token|access[_-]?token|auth[_-]?token)\s*[:=]\s*['"]?([a-zA-Z0-9\-_\.]{20,})['"]?`)
	secretPattern   = regexp.MustCompile(`(?i)(secret|client[_-]?secret)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{16,})['"]?`)
	privateKeyPattern = regexp.MustCompile(`-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----`)
	dbURLPattern   = regexp.MustCompile(`(?i)(mysql|postgres|postgresql|mongodb|redis|mssql|oracle)://[^\s:]+:[^\s@]+@[^\s/]+`)
	oauthPattern   = regexp.MustCompile(`(?i)(oauth|client[_-]?id)\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{20,})['"]?`)
	awsKeyPattern  = regexp.MustCompile(`(AKIA|ASIA)[A-Z0-9]{16}`)
	highEntropyPattern = regexp.MustCompile(`['"]([A-Za-z0-9+/]{32,}={0,2})['"]`)
)

func (d *SecretsDetector) Detect(content string, filename string) ([]Finding, error) {
	var findings []Finding
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if matches := passwordPattern.FindStringSubmatch(line); len(matches) > 2 {
			findings = append(findings, Finding{
				Rule:     d.Name(),
				Severity: High,
				File:     filename,
				Line:     lineNum + 1,
				Message:  "Possible password found",
			})
		}

		if matches := apiKeyPattern.FindStringSubmatch(line); len(matches) > 2 {
			findings = append(findings, Finding{
				Rule:     d.Name(),
				Severity: Critical,
				File:     filename,
				Line:     lineNum + 1,
				Message:  "Possible API key found",
			})
		}

		if matches := tokenPattern.FindStringSubmatch(line); len(matches) > 2 {
			findings = append(findings, Finding{
				Rule:     d.Name(),
				Severity: Critical,
				File:     filename,
				Line:     lineNum + 1,
				Message:  "Possible token found",
			})
		}

		if matches := secretPattern.FindStringSubmatch(line); len(matches) > 2 {
			findings = append(findings, Finding{
				Rule:     d.Name(),
				Severity: Critical,
				File:     filename,
				Line:     lineNum + 1,
				Message:  "Possible secret found",
			})
		}

		if privateKeyPattern.MatchString(line) {
			findings = append(findings, Finding{
				Rule:     d.Name(),
				Severity: Critical,
				File:     filename,
				Line:     lineNum + 1,
				Message:  "Private key found",
			})
		}

		if dbURLPattern.MatchString(line) {
			findings = append(findings, Finding{
				Rule:     d.Name(),
				Severity: High,
				File:     filename,
				Line:     lineNum + 1,
				Message:  "Database URL with credentials found",
			})
		}

		if matches := oauthPattern.FindStringSubmatch(line); len(matches) > 2 {
			findings = append(findings, Finding{
				Rule:     d.Name(),
				Severity: High,
				File:     filename,
				Line:     lineNum + 1,
				Message:  "Possible OAuth credential found",
			})
		}

		if awsKeyPattern.MatchString(line) {
			findings = append(findings, Finding{
				Rule:     d.Name(),
				Severity: Critical,
				File:     filename,
				Line:     lineNum + 1,
				Message:  "Possible AWS access key found",
			})
		}

		if matches := highEntropyPattern.FindStringSubmatch(line); len(matches) > 1 {
			if !strings.Contains(line, "data:") && !strings.Contains(line, "base64") {
				findings = append(findings, Finding{
					Rule:     d.Name(),
					Severity: Medium,
					File:     filename,
					Line:     lineNum + 1,
					Message:  "Possible high-entropy secret found",
				})
			}
		}
	}

	return findings, nil
}
