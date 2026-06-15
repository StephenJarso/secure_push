package detectors

import (
	"regexp"
	"strings"
)

type AuthDetector struct{}

func (d *AuthDetector) Name() string {
	return "AUTH_CREDENTIALS"
}

func (d *AuthDetector) Severity() Severity {
	return Critical
}

var (
	awsAccessKeyPattern        = regexp.MustCompile(`(AKIA|ASIA)[A-Z0-9]{16}`)
	githubTokenPattern         = regexp.MustCompile(`(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}`)
	gitlabTokenPattern         = regexp.MustCompile(`(glpat-)[A-Za-z0-9\-_]{20,}`)
	googleApiKeyPattern        = regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)
	bearerTokenPattern         = regexp.MustCompile(`bearer\s+[A-Za-z0-9\-_\.]+`)
	basicAuthPattern           = regexp.MustCompile(`basic\s+[A-Za-z0-9+/=]+`)
	jwtPattern                 = regexp.MustCompile(`eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.?[A-Za-z0-9\-_\.\/+=]*`)
	sshPrivateKeyPattern       = regexp.MustCompile(`-----BEGIN\s+(OPENSSH\s+)?PRIVATE\s+KEY-----`)
	pgpPrivateKeyPattern       = regexp.MustCompile(`-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----`)
	facebookTokenPattern       = regexp.MustCompile(`EAACEdEose0cBA[0-9A-Za-z]+`)
	twitterTokenPattern        = regexp.MustCompile(`[1-9][0-9]+-[0-9a-zA-Z]{40}`)
	herokuApiKeyPattern        = regexp.MustCompile(`[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`)
	mailgunApiKeyPattern       = regexp.MustCompile(`key-[0-9a-zA-Z]{32}`)
	twilioApiKeyPattern        = regexp.MustCompile(`SK[0-9a-fA-F]{32}`)
	stripeApiKeyPattern        = regexp.MustCompile(`(sk|pk)_(live|test)_[0-9a-zA-Z]{24,}`)
	sendgridApiKeyPattern      = regexp.MustCompile(`SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}`)
	slackTokenPattern          = regexp.MustCompile(`xox[baprs]-[A-Za-z0-9\-_]{10,}`)
	discordWebhookPattern      = regexp.MustCompile(`https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+`)
	telegramBotTokenPattern    = regexp.MustCompile(`[0-9]{8,10}:[A-Za-z0-9\-_]{35,}`)
	azureKeyPattern            = regexp.MustCompile(`-----BEGIN AZURE KEY VAULT-----`)
	personalAccessTokenPattern = regexp.MustCompile(`[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{60,}`)
	figmaTokenPattern          = regexp.MustCompile(`figd_[A-Za-z0-9]{60,}`)
	notionTokenPattern         = regexp.MustCompile(`secret_[A-Za-z0-9]{43}`)
	linearTokenPattern         = regexp.MustCompile(`lin_api_[A-Za-z0-9]{64}`)
	intercomTokenPattern       = regexp.MustCompile(`(?i)(intercom(?:_|[-[:space:]])?(?:access[_-]?)?token|access[_-]?token)\s*[:=]\s*['"]?[A-Za-z0-9]{40,}['"]?`)
	auth0TokenPattern          = regexp.MustCompile(`[A-Za-z0-9\-_]{80,}\.[A-Za-z0-9\-_]{32,}`)
)

type authRule struct {
	pattern  *regexp.Regexp
	message  string
	severity Severity
}

var providerAuthRules = []authRule{
	{pattern: figmaTokenPattern, message: "Figma token found", severity: High},
	{pattern: notionTokenPattern, message: "Notion token found", severity: High},
	{pattern: linearTokenPattern, message: "Linear API token found", severity: High},
	{pattern: auth0TokenPattern, message: "Auth0 token found", severity: High},
	{pattern: intercomTokenPattern, message: "Intercom token found", severity: High},
}

func (d *AuthDetector) Detect(content string, filename string) ([]Finding, error) {
	var findings []Finding
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if awsAccessKeyPattern.MatchString(line) {
			findings = append(findings, Finding{
				Rule:     d.Name(),
				Severity: Critical,
				File:     filename,
				Line:     lineNum + 1,
				Message:  "AWS Access Key ID found",
			})
		}

		if matches := githubTokenPattern.FindStringSubmatch(line); len(matches) > 0 {
			findings = append(findings, Finding{
				Rule:     d.Name(),
				Severity: Critical,
				File:     filename,
				Line:     lineNum + 1,
				Message:  "GitHub token found",
			})
		}

		if gitlabTokenPattern.MatchString(line) {
			findings = append(findings, Finding{
				Rule:     d.Name(),
				Severity: Critical,
				File:     filename,
				Line:     lineNum + 1,
				Message:  "GitLab token found",
			})
		}

		if googleApiKeyPattern.MatchString(line) {
			findings = append(findings, Finding{
				Rule:     d.Name(),
				Severity: High,
				File:     filename,
				Line:     lineNum + 1,
				Message:  "Google API key found",
			})
		}

		if matches := bearerTokenPattern.FindStringSubmatch(strings.ToLower(line)); len(matches) > 0 {
			findings = append(findings, Finding{
				Rule:     d.Name(),
				Severity: High,
				File:     filename,
				Line:     lineNum + 1,
				Message:  "Bearer token found",
			})
		}

		if matches := basicAuthPattern.FindStringSubmatch(strings.ToLower(line)); len(matches) > 0 {
			findings = append(findings, Finding{
				Rule:     d.Name(),
				Severity: High,
				File:     filename,
				Line:     lineNum + 1,
				Message:  "Basic auth credentials found",
			})
		}

		if jwtPattern.MatchString(line) {
			findings = append(findings, Finding{
				Rule:     d.Name(),
				Severity: High,
				File:     filename,
				Line:     lineNum + 1,
				Message:  "JWT token found",
			})
		}

		if sshPrivateKeyPattern.MatchString(line) {
			findings = append(findings, Finding{
				Rule:     d.Name(),
				Severity: Critical,
				File:     filename,
				Line:     lineNum + 1,
				Message:  "SSH private key found",
			})
		}

		if pgpPrivateKeyPattern.MatchString(line) {
			findings = append(findings, Finding{
				Rule:     d.Name(),
				Severity: Critical,
				File:     filename,
				Line:     lineNum + 1,
				Message:  "PGP private key found",
			})
		}

		if facebookTokenPattern.MatchString(line) {
			findings = append(findings, Finding{
				Rule:     d.Name(),
				Severity: High,
				File:     filename,
				Line:     lineNum + 1,
				Message:  "Facebook access token found",
			})
		}

		if twitterTokenPattern.MatchString(line) {
			findings = append(findings, Finding{
				Rule:     d.Name(),
				Severity: High,
				File:     filename,
				Line:     lineNum + 1,
				Message:  "Twitter access token found",
			})
		}

		if herokuApiKeyPattern.MatchString(line) {
			findings = append(findings, Finding{
				Rule:     d.Name(),
				Severity: High,
				File:     filename,
				Line:     lineNum + 1,
				Message:  "Heroku API key found",
			})
		}

		if mailgunApiKeyPattern.MatchString(line) {
			findings = append(findings, Finding{
				Rule:     d.Name(),
				Severity: High,
				File:     filename,
				Line:     lineNum + 1,
				Message:  "Mailgun API key found",
			})
		}

		if twilioApiKeyPattern.MatchString(line) {
			findings = append(findings, Finding{
				Rule:     d.Name(),
				Severity: High,
				File:     filename,
				Line:     lineNum + 1,
				Message:  "Twilio API key found",
			})
		}

		if stripeApiKeyPattern.MatchString(line) {
			findings = append(findings, Finding{
				Rule:     d.Name(),
				Severity: Critical,
				File:     filename,
				Line:     lineNum + 1,
				Message:  "Stripe API key found",
			})
		}

		if sendgridApiKeyPattern.MatchString(line) {
			findings = append(findings, Finding{
				Rule:     d.Name(),
				Severity: High,
				File:     filename,
				Line:     lineNum + 1,
				Message:  "SendGrid API key found",
			})
		}

		if slackTokenPattern.MatchString(line) {
			findings = append(findings, Finding{
				Rule:     d.Name(),
				Severity: Critical,
				File:     filename,
				Line:     lineNum + 1,
				Message:  "Slack token found",
			})
		}

		if discordWebhookPattern.MatchString(line) {
			findings = append(findings, Finding{
				Rule:     d.Name(),
				Severity: High,
				File:     filename,
				Line:     lineNum + 1,
				Message:  "Discord webhook URL found",
			})
		}

		if telegramBotTokenPattern.MatchString(line) {
			findings = append(findings, Finding{
				Rule:     d.Name(),
				Severity: High,
				File:     filename,
				Line:     lineNum + 1,
				Message:  "Telegram bot token found",
			})
		}

		if azureKeyPattern.MatchString(line) {
			findings = append(findings, Finding{
				Rule:     d.Name(),
				Severity: Critical,
				File:     filename,
				Line:     lineNum + 1,
				Message:  "Azure Key Vault found",
			})
		}

		if personalAccessTokenPattern.MatchString(line) {
			findings = append(findings, Finding{
				Rule:     d.Name(),
				Severity: High,
				File:     filename,
				Line:     lineNum + 1,
				Message:  "Personal access token found",
			})
		}

		seenProviderFindings := make(map[string]struct{}, len(providerAuthRules))
		for _, rule := range providerAuthRules {
			if rule.pattern.MatchString(line) {
				if _, seen := seenProviderFindings[rule.message]; seen {
					continue
				}
				findings = append(findings, Finding{
					Rule:     d.Name(),
					Severity: rule.severity,
					File:     filename,
					Line:     lineNum + 1,
					Message:  rule.message,
				})
				seenProviderFindings[rule.message] = struct{}{}
			}
		}
	}

	return findings, nil
}
