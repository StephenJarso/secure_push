package detectors

import (
	"testing"
)

func TestEnvDetector_Name(t *testing.T) {
	d := &EnvDetector{}
	if got := d.Name(); got != "ENV_FILE" {
		t.Errorf("Name() = %v, want %v", got, "ENV_FILE")
	}
}

func TestEnvDetector_Severity(t *testing.T) {
	d := &EnvDetector{}
	if got := d.Severity(); got != Critical {
		t.Errorf("Severity() = %v, want %v", got, Critical)
	}
}

func TestEnvDetector_Detect(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		content  string
		wantLen  int
		wantMsg  string
	}{
		{
			name:     "dotenv file",
			filename: ".env",
			content:  "KEY=value",
			wantLen:  1,
			wantMsg:  ".env file should not be committed",
		},
		{
			name:     "dotenv local file",
			filename: ".env.local",
			content:  "KEY=value",
			wantLen:  1,
			wantMsg:  ".env file should not be committed",
		},
		{
			name:     "dotenv development file",
			filename: ".env.development",
			content:  "KEY=value",
			wantLen:  1,
			wantMsg:  ".env file should not be committed",
		},
		{
			name:     "dotenv production file",
			filename: ".env.production",
			content:  "KEY=value",
			wantLen:  1,
			wantMsg:  ".env file should not be committed",
		},
		{
			name:     "dotenv test file",
			filename: ".env.test",
			content:  "KEY=value",
			wantLen:  1,
			wantMsg:  ".env file should not be committed",
		},
		{
			name:     "dotenv uppercase",
			filename: ".ENV",
			content:  "KEY=value",
			wantLen:  1,
			wantMsg:  ".env file should not be committed",
		},
		{
			name:     "dotenv mixed case",
			filename: ".Env",
			content:  "KEY=value",
			wantLen:  1,
			wantMsg:  ".env file should not be committed",
		},
		{
			name:     "env file",
			filename: "env",
			content:  "KEY=value",
			wantLen:  1,
			wantMsg:  "env file should not be committed",
		},
		{
			name:     "env local file",
			filename: "env.local",
			content:  "KEY=value",
			wantLen:  1,
			wantMsg:  "env file should not be committed",
		},
		{
			name:     "env development file",
			filename: "env.development",
			content:  "KEY=value",
			wantLen:  1,
			wantMsg:  "env file should not be committed",
		},
		{
			name:     "env uppercase",
			filename: "ENV",
			content:  "KEY=value",
			wantLen:  1,
			wantMsg:  "env file should not be committed",
		},
		{
			name:     "regular file",
			filename: "main.go",
			content:  "package main",
			wantLen:  0,
		},
		{
			name:     "regular file with env in name",
			filename: "environment.go",
			content:  "package main",
			wantLen:  0,
		},
		{
			name:     "regular file with dotenv in name",
			filename: "dotenv.go",
			content:  "package main",
			wantLen:  0,
		},
		{
			name:     "empty content",
			filename: ".env",
			content:  "",
			wantLen:  1,
			wantMsg:  ".env file should not be committed",
		},
		{
			name:     "path with directory",
			filename: "config/.env",
			content:  "KEY=value",
			wantLen:  1,
			wantMsg:  ".env file should not be committed",
		},
		{
			name:     "path with nested directory",
			filename: "config/development/.env.local",
			content:  "KEY=value",
			wantLen:  1,
			wantMsg:  ".env file should not be committed",
		},
		{
			name:     "envrc file",
			filename: ".envrc",
			content:  "export KEY=value",
			wantLen:  1,
			wantMsg:  ".env file should not be committed",
		},
		{
			name:     "envrc file with env prefix",
			filename: ".envrc.local",
			content:  "export KEY=value",
			wantLen:  1,
			wantMsg:  ".env file should not be committed",
		},
		{
			name:     "envrc mixed case",
			filename: ".Envrc",
			content:  "export KEY=value",
			wantLen:  1,
			wantMsg:  ".env file should not be committed",
		},
		{
			name:     "envrc uppercase",
			filename: ".ENVRC",
			content:  "export KEY=value",
			wantLen:  1,
			wantMsg:  ".env file should not be committed",
		},
		{
			name:     "env example file",
			filename: ".env.example",
			content:  "KEY=value",
			wantLen:  1,
			wantMsg:  ".env file should not be committed",
		},
		{
			name:     "env sample file",
			filename: ".env.sample",
			content:  "KEY=value",
			wantLen:  1,
			wantMsg:  ".env file should not be committed",
		},
		{
			name:     "envrc production",
			filename: ".envrc.production",
			content:  "export KEY=value",
			wantLen:  1,
			wantMsg:  ".env file should not be committed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &EnvDetector{}
			got, err := d.Detect(tt.content, tt.filename)
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}
			if len(got) != tt.wantLen {
				t.Fatalf("Detect() returned %d findings, want %d", len(got), tt.wantLen)
			}
			if tt.wantLen > 0 {
				if got[0].Rule != "ENV_FILE" {
					t.Errorf("Rule = %v, want %v", got[0].Rule, "ENV_FILE")
				}
				if got[0].Severity != Critical {
					t.Errorf("Severity = %v, want %v", got[0].Severity, Critical)
				}
				if got[0].File != tt.filename {
					t.Errorf("File = %v, want %v", got[0].File, tt.filename)
				}
				if got[0].Message != tt.wantMsg {
					t.Errorf("Message = %v, want %v", got[0].Message, tt.wantMsg)
				}
				if got[0].Line != 1 {
					t.Errorf("Line = %v, want %v", got[0].Line, 1)
				}
			}
		})
	}
}

func TestEnvDetector_Detect_NoError(t *testing.T) {
	d := &EnvDetector{}
	_, err := d.Detect("some content", "main.go")
	if err != nil {
		t.Fatalf("Detect() error = %v, want nil", err)
	}
}
