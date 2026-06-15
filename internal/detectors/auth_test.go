package detectors

import (
	"testing"
)

func TestAuthDetector_Name(t *testing.T) {
	d := &AuthDetector{}
	if got := d.Name(); got != "AUTH_CREDENTIALS" {
		t.Errorf("Name() = %v, want %v", got, "AUTH_CREDENTIALS")
	}
}

func TestAuthDetector_Severity(t *testing.T) {
	d := &AuthDetector{}
	if got := d.Severity(); got != Critical {
		t.Errorf("Severity() = %v, want %v", got, Critical)
	}
}

func TestAuthDetector_Detect(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		content  string
		wantMin  int
	}{
		{
			name:     "aws access key",
			filename: "config.go",
			content:  "aws_key = 'AKIAIOSFODNN7EXAMPLE'",
			wantMin:  1,
		},
		{
			name:     "github token",
			filename: "config.go",
			content:  "github_token = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef01234567'",
			wantMin:  1,
		},
		{
			name:     "gitlab token",
			filename: "config.go",
			content:  "gitlab_token = 'glpat-abcdefghijklmnopqrstuv'",
			wantMin:  1,
		},
		{
			name:     "google api key",
			filename: "config.go",
			content:  "google_api_key = 'AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY'",
			wantMin:  1,
		},
		{
			name:     "bearer token",
			filename: "config.go",
			content:  "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			wantMin:  1,
		},
		{
			name:     "basic auth",
			filename: "config.go",
			content:  "Authorization: Basic dXNlcjpwYXNzd29yZA==",
			wantMin:  1,
		},
		{
			name:     "jwt token",
			filename: "config.go",
			content:  "jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'",
			wantMin:  1,
		},
		{
			name:     "ssh private key",
			filename: "id_rsa",
			content:  "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n-----END OPENSSH PRIVATE KEY-----",
			wantMin:  1,
		},
		{
			name:     "pgp private key",
			filename: "key.gpg",
			content:  "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v2\n\nmQINBF...\n-----END PGP PRIVATE KEY BLOCK-----",
			wantMin:  1,
		},
		{
			name:     "facebook token",
			filename: "config.go",
			content:  "fb_token = 'EAACEdEose0cBA1234567890'",
			wantMin:  1,
		},
		{
			name:     "twitter token",
			filename: "config.go",
			content:  "twitter_token = '1234567890-abcdefghijklmnopqrstuvwxyz0123456789012345'",
			wantMin:  1,
		},
		{
			name:     "heroku api key",
			filename: "config.go",
			content:  "heroku_key = 'heroku:12345678-1234-1234-1234-123456789012'",
			wantMin:  1,
		},
		{
			name:     "mailgun api key",
			filename: "config.go",
			content:  "mailgun_key = 'key-abcdefghijklmnopqrstuvwxyz012345'",
			wantMin:  1,
		},
		{
			name:     "multiple auth credentials",
			filename: "config.go",
			content:  "github_token = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef01234567'\naws_key = 'AKIAIOSFODNN7EXAMPLE'\nheroku_key = 'heroku:12345678-1234-1234-1234-123456789012'",
			wantMin:  3,
		},
		{
			name:     "no auth credentials",
			filename: "main.go",
			content:  "package main\n\nfunc main() {\n\tprintln(\"hello\")\n}",
			wantMin:  0,
		},
		{
			name:     "commented token ignored",
			filename: "config.go",
			content:  "# github_token = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef'",
			wantMin:  0,
		},
		{
			name:     "empty content",
			filename: "config.go",
			content:  "",
			wantMin:  0,
		},
		{
			name:     "slack token",
			filename: "config.go",
			content:  "slack_token = 'xoxb-test0000000-test00000000000-TESTTESTTEST'",
			wantMin:  1,
		},
		{
			name:     "discord webhook",
			filename: "config.go",
			content:  "discord_webhook = 'https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'",
			wantMin:  1,
		},
		{
			name:     "telegram bot token",
			filename: "config.go",
			content:  "telegram_token = '1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghiJKLMNO'",
			wantMin:  1,
		},
		{
			name:     "azure key vault",
			filename: "azure.key",
			content:  "-----BEGIN AZURE KEY VAULT-----\nkey-data\n-----END AZURE KEY VAULT-----",
			wantMin:  1,
		},
		{
			name:     "personal access token",
			filename: "config.go",
			content:  "pat = 'abc123def456ghij789klmn.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ'",
			wantMin:  1,
		},
		{
			name:     "multiple slack tokens",
			filename: "config.go",
			content:  "token1 = 'xoxb-test0000000-test00000000000-TESTTESTTEST'\ntoken2 = 'xoxa-test0000000-test00000000000-TESTTESTTEST'",
			wantMin:  2,
		},
		{
			name:     "figma token",
			filename: "config.go",
			content:  "figma_token = 'figd_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH'",
			wantMin:  1,
		},
		{
			name:     "notion token",
			filename: "config.go",
			content:  "notion_token = 'secret_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrs'",
			wantMin:  1,
		},
		{
			name:     "linear api token",
			filename: "config.go",
			content:  "linear_api_token = 'lin_api_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH'",
			wantMin:  1,
		},
		{
			name:     "auth0 token",
			filename: "config.go",
			content:  "auth0_token = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl'",
			wantMin:  1,
		},
		{
			name:     "intercom token",
			filename: "config.go",
			content:  "intercom_token = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'",
			wantMin:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &AuthDetector{}
			got, err := d.Detect(tt.content, tt.filename)
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}
			if len(got) < tt.wantMin {
				t.Fatalf("Detect() returned %d findings, want at least %d", len(got), tt.wantMin)
			}
			for _, f := range got {
				if f.Rule != "AUTH_CREDENTIALS" {
					t.Errorf("Rule = %v, want %v", f.Rule, "AUTH_CREDENTIALS")
				}
				if f.File != tt.filename {
					t.Errorf("File = %v, want %v", f.File, tt.filename)
				}
				if f.Line < 1 {
					t.Errorf("Line = %v, want >= 1", f.Line)
				}
			}
		})
	}
}

func TestAuthDetector_Detect_NoError(t *testing.T) {
	d := &AuthDetector{}
	_, err := d.Detect("some content", "main.go")
	if err != nil {
		t.Fatalf("Detect() error = %v, want nil", err)
	}
}

func TestAuthDetector_DetectProviderMessages(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "figma",
			content: "figma_token = 'figd_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH'",
			want:    "Figma token found",
		},
		{
			name:    "notion",
			content: "notion_token = 'secret_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrs'",
			want:    "Notion token found",
		},
		{
			name:    "linear",
			content: "linear_api_token = 'lin_api_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH'",
			want:    "Linear API token found",
		},
		{
			name:    "auth0",
			content: "auth0_token = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl'",
			want:    "Auth0 token found",
		},
		{
			name:    "intercom",
			content: "intercom_token = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'",
			want:    "Intercom token found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &AuthDetector{}
			got, err := d.Detect(tt.content, "config.go")
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}
			if len(got) != 1 {
				t.Fatalf("Detect() returned %d findings, want 1", len(got))
			}
			if got[0].Message != tt.want {
				t.Errorf("Message = %q, want %q", got[0].Message, tt.want)
			}
		})
	}
}

func TestAuthDetector_DetectProviderLineNumbers(t *testing.T) {
	d := &AuthDetector{}
	got, err := d.Detect("line1\nintercom_token = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'", "config.go")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("Detect() returned %d findings, want 1", len(got))
	}
	if got[0].Line != 2 {
		t.Errorf("Line = %d, want 2", got[0].Line)
	}
}

func TestAuthDetector_DetectProviderWhitespaceComments(t *testing.T) {
	d := &AuthDetector{}
	got, err := d.Detect("  # intercom_token = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'", "config.go")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("Detect() returned %d findings, want 0", len(got))
	}
}
