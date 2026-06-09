package config

import (
	"os"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.MaxFileSize != 10*1024*1024 {
		t.Errorf("MaxFileSize = %d, want %d", cfg.MaxFileSize, 10*1024*1024)
	}

	if cfg.Severity != "medium" {
		t.Errorf("Severity = %s, want medium", cfg.Severity)
	}

	if len(cfg.IgnoreFiles) == 0 {
		t.Error("IgnoreFiles should not be empty")
	}
}

func TestLoadNonExistentConfig(t *testing.T) {
	cfg, err := Load("/nonexistent/path/to/config.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
}

func TestLoadValidConfig(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "secure-push-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	content := `
ignore_patterns:
  - "*.test"
  - "vendor/**"
ignore_files:
  - ".git/**"
  - "node_modules/**"
max_file_size: 5242880
severity: high
enable_detectors:
  - "ENV_FILE"
disable_detectors:
  - "CONFIG_FILE"
`
	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	tmpFile.Close()

	cfg, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.IgnorePatterns) != 2 {
		t.Errorf("IgnorePatterns = %d, want 2", len(cfg.IgnorePatterns))
	}

	if cfg.MaxFileSize != 5*1024*1024 {
		t.Errorf("MaxFileSize = %d, want %d", cfg.MaxFileSize, 5*1024*1024)
	}

	if cfg.Severity != "high" {
		t.Errorf("Severity = %s, want high", cfg.Severity)
	}
}

func TestShouldIgnore(t *testing.T) {
	cfg := &Config{
		IgnorePatterns: []string{"*.test", "vendor/**"},
		IgnoreFiles:    []string{".git/**", "node_modules/**"},
	}

	tests := []struct {
		path   string
		ignore bool
	}{
		{"main.go", false},
		{"main.test.go", true},
		{"vendor/github.com/pkg/errors/errors.go", true},
		{".git/config", true},
		{"node_modules/package/index.js", true},
		{"internal/scanner/scanner.go", false},
		{"README.md", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := cfg.ShouldIgnore(tt.path)
			if got != tt.ignore {
				t.Errorf("ShouldIgnore(%q) = %v, want %v", tt.path, got, tt.ignore)
			}
		})
	}
}

func TestIsSeverityEnabled(t *testing.T) {
	tests := []struct {
		severity string
		check    Severity
		want     bool
	}{
		{"low", Low, true},
		{"low", Medium, false},
		{"medium", Low, false},
		{"medium", Medium, true},
		{"medium", High, true},
		{"medium", Critical, true},
		{"high", Low, false},
		{"high", Medium, false},
		{"high", High, true},
		{"high", Critical, true},
		{"critical", Low, false},
		{"critical", Medium, false},
		{"critical", High, false},
		{"critical", Critical, true},
		{"unknown", Critical, true},
	}

	for _, tt := range tests {
		t.Run(tt.severity+"_"+string(tt.check), func(t *testing.T) {
			cfg := &Config{Severity: tt.severity}
			got := cfg.IsSeverityEnabled(tt.check)
			if got != tt.want {
				t.Errorf("IsSeverityEnabled(%q, %v) = %v, want %v", tt.severity, tt.check, got, tt.want)
			}
		})
	}
}

func TestIsDetectorEnabled(t *testing.T) {
	tests := []struct {
		name            string
		enable          []string
		disable         []string
		detector        string
		want            bool
	}{
		{"no restrictions", nil, nil, "ENV_FILE", true},
		{"enabled list", []string{"ENV_FILE", "SECRETS"}, nil, "ENV_FILE", true},
		{"enabled list not found", []string{"ENV_FILE"}, nil, "SECRETS", false},
		{"disabled list", nil, []string{"CONFIG_FILE"}, "CONFIG_FILE", false},
		{"disabled list not found", nil, []string{"CONFIG_FILE"}, "ENV_FILE", true},
		{"both enabled and disabled", []string{"ENV_FILE"}, []string{"SECRETS"}, "ENV_FILE", true},
		{"case insensitive", []string{"env_file"}, nil, "ENV_FILE", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				EnableDetectors:  tt.enable,
				DisableDetectors: tt.disable,
			}
			got := cfg.IsDetectorEnabled(tt.detector)
			if got != tt.want {
				t.Errorf("IsDetectorEnabled(%q) = %v, want %v", tt.detector, got, tt.want)
			}
		})
	}
}

func TestFindConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	if findConfigFile() != "" {
		t.Error("expected empty string when no config file exists")
	}

	os.WriteFile(".secure-push.yaml", []byte("test: value"), 0644)
	if found := findConfigFile(); found != ".secure-push.yaml" {
		t.Errorf("findConfigFile() = %s, want .secure-push.yaml", found)
	}
}
