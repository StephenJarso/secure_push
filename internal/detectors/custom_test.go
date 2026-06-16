package detectors

import (
	"os"
	"testing"
)

func TestCustomRuleDetector_Name(t *testing.T) {
	d := &CustomRuleDetector{}
	if got := d.Name(); got != "CUSTOM_RULE" {
		t.Errorf("Name() = %v, want %v", got, "CUSTOM_RULE")
	}
}

func TestCustomRuleDetector_Severity(t *testing.T) {
	d := &CustomRuleDetector{}
	if got := d.Severity(); got != Medium {
		t.Errorf("Severity() = %v, want %v", got, Medium)
	}
}

func TestCustomRuleDetector_LoadRules(t *testing.T) {
	d := &CustomRuleDetector{}
	tmpFile, err := os.CreateTemp("", "custom-rules-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	content := `
- name: "Test Rule"
  pattern: "secret[0-9]+"
  severity: "HIGH"
  message: "Test secret found"
`
	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	if err := d.LoadRules(tmpFile.Name()); err != nil {
		t.Fatalf("LoadRules() error = %v", err)
	}

	if len(d.rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(d.rules))
	}
}

func TestCustomRuleDetector_LoadRulesInvalidFile(t *testing.T) {
	d := &CustomRuleDetector{}
	err := d.LoadRules("/nonexistent/path/rules.yaml")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestCustomRuleDetector_Detect(t *testing.T) {
	d := &CustomRuleDetector{}
	d.rules = []CustomRuleConfig{
		{
			Name:     "Test Rule",
			Pattern:  "secret[0-9]+",
			Severity: "HIGH",
			Message:  "Test secret found",
		},
	}

	got, err := d.Detect("my secret123 here", "test.go")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(got) != 1 {
		t.Errorf("Detect() returned %d findings, want 1", len(got))
	}
	if got[0].Severity != High {
		t.Errorf("Severity = %v, want HIGH", got[0].Severity)
	}
	if got[0].Message != "Test secret found" {
		t.Errorf("Message = %v, want 'Test secret found'", got[0].Message)
	}
}

func TestCustomRuleDetector_DetectNoMatch(t *testing.T) {
	d := &CustomRuleDetector{}
	d.rules = []CustomRuleConfig{
		{
			Name:     "Test Rule",
			Pattern:  "secret[0-9]+",
			Severity: "HIGH",
			Message:  "Test secret found",
		},
	}

	got, err := d.Detect("no secrets here", "test.go")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Detect() returned %d findings, want 0", len(got))
	}
}

func TestCustomRuleDetector_DetectInvalidRegex(t *testing.T) {
	d := &CustomRuleDetector{}
	d.rules = []CustomRuleConfig{
		{
			Name:     "Bad Rule",
			Pattern:  "[invalid",
			Severity: "HIGH",
			Message:  "Bad rule",
		},
	}

	got, err := d.Detect("some content", "test.go")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Detect() returned %d findings, want 0", len(got))
	}
}

func TestCustomRuleDetector_DetectDefaultMessage(t *testing.T) {
	d := &CustomRuleDetector{}
	d.rules = []CustomRuleConfig{
		{
			Name:     "Test Rule",
			Pattern:  "secret[0-9]+",
			Severity: "HIGH",
		},
	}

	got, err := d.Detect("my secret123 here", "test.go")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(got) != 1 {
		t.Errorf("Detect() returned %d findings, want 1", len(got))
	}
	if got[0].Message != "Custom rule 'Test Rule' matched" {
		t.Errorf("Message = %v, want default message", got[0].Message)
	}
}
