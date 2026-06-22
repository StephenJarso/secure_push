package detectors

import (
	"testing"
)

func TestCustomRuleDetector_AddRule(t *testing.T) {
	d := &CustomRuleDetector{}

	rule := CustomRuleConfig{
		Name:     "Test Rule",
		Pattern:  "secret[0-9]+",
		Severity: "HIGH",
		Message:  "Test secret found",
	}

	if err := d.AddRule(rule); err != nil {
		t.Fatalf("AddRule() error = %v", err)
	}

	if d.RuleCount() != 1 {
		t.Errorf("RuleCount() = %d, want 1", d.RuleCount())
	}
}

func TestCustomRuleDetector_AddRuleInvalidPattern(t *testing.T) {
	d := &CustomRuleDetector{}

	rule := CustomRuleConfig{
		Name:     "Bad Rule",
		Pattern:  "[invalid",
		Severity: "HIGH",
	}

	if err := d.AddRule(rule); err == nil {
		t.Error("AddRule() should return error for invalid pattern")
	}
}

func TestCustomRuleDetector_RuleCount(t *testing.T) {
	d := &CustomRuleDetector{}

	if d.RuleCount() != 0 {
		t.Errorf("RuleCount() = %d, want 0", d.RuleCount())
	}

	d.rules = []CustomRuleConfig{
		{Name: "Rule 1", Pattern: "test1"},
		{Name: "Rule 2", Pattern: "test2"},
	}

	if d.RuleCount() != 2 {
		t.Errorf("RuleCount() = %d, want 2", d.RuleCount())
	}
}

func TestCustomRuleDetector_DetectMultipleRules(t *testing.T) {
	d := &CustomRuleDetector{}
	d.rules = []CustomRuleConfig{
		{Name: "Rule 1", Pattern: "secret[0-9]+", Severity: "HIGH"},
		{Name: "Rule 2", Pattern: "password[0-9]+", Severity: "CRITICAL"},
	}

	content := "my secret123 and password456 here"
	got, err := d.Detect(content, "test.go")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(got) < 2 {
		t.Errorf("Detect() returned %d findings, want at least 2", len(got))
	}
}
