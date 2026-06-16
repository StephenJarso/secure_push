package config

import (
	"os"
	"testing"
)

func TestDefaultConfig_ExitCode(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.ExitCode != 1 {
		t.Errorf("ExitCode = %d, want 1", cfg.ExitCode)
	}
}

func TestLoadConfig_ExitCode(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "secure-push-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	content := "exit_code: 2\n"
	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	tmpFile.Close()

	cfg, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.ExitCode != 2 {
		t.Errorf("ExitCode = %d, want 2", cfg.ExitCode)
	}
}

func TestLoadConfig_ExitCodeDefault(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "secure-push-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	content := "severity_threshold: high\n"
	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	tmpFile.Close()

	cfg, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.ExitCode != 1 {
		t.Errorf("ExitCode = %d, want 1 (default)", cfg.ExitCode)
	}
}
