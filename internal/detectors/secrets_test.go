package detectors

import (
	"testing"
)

func TestSecretsDetector_Name(t *testing.T) {
	d := &SecretsDetector{}
	if got := d.Name(); got != "SECRETS" {
		t.Errorf("Name() = %v, want %v", got, "SECRETS")
	}
}

func TestSecretsDetector_Severity(t *testing.T) {
	d := &SecretsDetector{}
	if got := d.Severity(); got != Critical {
		t.Errorf("Severity() = %v, want %v", got, Critical)
	}
}

func TestSecretsDetector_Detect(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		content  string
		wantMin  int
	}{
		{
			name:     "password in env file",
			filename: "config.go",
			content:  "password = 'super_secret_pass123'",
			wantMin:  1,
		},
		{
			name:     "api key",
			filename: "config.go",
			content:  "api_key = 'abcdefghijklmnopqrstuvwxyz1234567890'",
			wantMin:  1,
		},
		{
			name:     "token",
			filename: "config.go",
			content:  "token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'",
			wantMin:  1,
		},
		{
			name:     "secret",
			filename: "config.go",
			content:  "client_secret = 'abcdefghijklmnopqrstuvwx'",
			wantMin:  1,
		},
		{
			name:     "private key",
			filename: "key.pem",
			content:  "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----",
			wantMin:  1,
		},
		{
			name:     "database url",
			filename: "config.go",
			content:  "db_url = 'postgres://user:password@localhost:5432/mydb'",
			wantMin:  1,
		},
		{
			name:     "mysql url",
			filename: "config.go",
			content:  "db_url = 'mysql://admin:secret123@db.example.com:3306/production'",
			wantMin:  1,
		},
		{
			name:     "mongodb url",
			filename: "config.go",
			content:  "db_url = 'mongodb://user:pass@mongo.example.com:27017/app'",
			wantMin:  1,
		},
		{
			name:     "aws key",
			filename: "config.go",
			content:  "aws_key = 'AKIAIOSFODNN7EXAMPLE'",
			wantMin:  1,
		},
		{
			name:     "high entropy string",
			filename: "config.go",
			content:  "secret = 'aB3dE4fG5hI6jK7lM8nO9pQ0rS1tU2vW3xY4zZ5'",
			wantMin:  1,
		},
		{
			name:     "multiple secrets",
			filename: "config.go",
			content:  "password = 'secret123'\napikey = 'abcdefghijklmnopqrstuvwxyz1234567890'\ntoken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'",
			wantMin:  3,
		},
		{
			name:     "no secrets",
			filename: "main.go",
			content:  "package main\n\nfunc main() {\n\tprintln(\"hello\")\n}",
			wantMin:  0,
		},
		{
			name:     "commented password ignored",
			filename: "config.go",
			content:  "# password = 'secret123'",
			wantMin:  0,
		},
		{
			name:     "empty content",
			filename: "config.go",
			content:  "",
			wantMin:  0,
		},
		{
			name:     "short password ignored",
			filename: "config.go",
			content:  "password = 'short'",
			wantMin:  0,
		},
		{
			name:     "base64 data uri ignored",
			filename: "config.go",
			content:  "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
			wantMin:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &SecretsDetector{}
			got, err := d.Detect(tt.content, tt.filename)
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}
			if len(got) < tt.wantMin {
				t.Fatalf("Detect() returned %d findings, want at least %d", len(got), tt.wantMin)
			}
			for _, f := range got {
				if f.Rule != "SECRETS" {
					t.Errorf("Rule = %v, want %v", f.Rule, "SECRETS")
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

func TestSecretsDetector_Detect_NoError(t *testing.T) {
	d := &SecretsDetector{}
	_, err := d.Detect("some content", "main.go")
	if err != nil {
		t.Fatalf("Detect() error = %v, want nil", err)
	}
}
