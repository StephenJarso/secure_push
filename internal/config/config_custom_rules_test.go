package config

import (
	"os"
	"testing"
)

func TestDefaultConfig_CustomRuleFiles(t *testing.T) {
	cfg := DefaultConfig()
	if len(cfg.CustomRuleFiles) != 0 {
		t.Errorf("CustomRuleFiles = %v, want empty slice", cfg.CustomRuleFiles)
	}
}

func TestLoadConfig_CustomRuleFiles(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "secure-push-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	content := "custom_rule_files:\n  - rules/custom-secrets.yaml\n  - rules/custom-api-keys.yaml\n"
	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	tmpFile.Close()

	cfg, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.CustomRuleFiles) != 2 {
		t.Errorf("CustomRuleFiles = %v, want 2 files", cfg.CustomRuleFiles)
	}
}

func TestLoadConfig_CustomRuleFilesDefault(t *testing.T) {
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

	if len(cfg.CustomRuleFiles) != 0 {
		t.Errorf("CustomRuleFiles = %v, want empty slice (default)", cfg.CustomRuleFiles)
	}
}
