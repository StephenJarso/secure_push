package config

import (
	"testing"
)

func TestConfig_CustomRuleCount(t *testing.T) {
	cfg := &Config{
		CustomRules: []CustomRule{
			{Path: "test1.go", Severity: "high"},
			{Path: "test2.go", Severity: "medium"},
		},
	}

	if cfg.CustomRuleCount() != 2 {
		t.Errorf("CustomRuleCount() = %d, want 2", cfg.CustomRuleCount())
	}
}

func TestConfig_IgnoreRuleCount(t *testing.T) {
	cfg := &Config{
		IgnoreRules: []string{"ENV_FILE", "CONFIG_FILE"},
	}

	if cfg.IgnoreRuleCount() != 2 {
		t.Errorf("IgnoreRuleCount() = %d, want 2", cfg.IgnoreRuleCount())
	}
}

func TestConfig_IgnorePathCount(t *testing.T) {
	cfg := &Config{
		IgnorePaths: []string{"*.test.go", "vendor/**"},
	}

	if cfg.IgnorePathCount() != 2 {
		t.Errorf("IgnorePathCount() = %d, want 2", cfg.IgnorePathCount())
	}
}

func TestConfig_AllowlistCount(t *testing.T) {
	cfg := &Config{
		Allowlist: []string{"important.test.go", "config.go"},
	}

	if cfg.AllowlistCount() != 2 {
		t.Errorf("AllowlistCount() = %d, want 2", cfg.AllowlistCount())
	}
}