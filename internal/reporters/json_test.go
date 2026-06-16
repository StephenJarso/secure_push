package reporters

import (
	"testing"

	"secure-push/internal/detectors"
)

func TestJSONReporter_NoFindings(t *testing.T) {
	reporter := &JSONReporter{}
	err := reporter.Report([]detectors.Finding{})
	if err != nil {
		t.Errorf("Expected no error for empty findings, got: %v", err)
	}
}

func TestJSONReporter_WithFindings(t *testing.T) {
	reporter := &JSONReporter{}
	findings := []detectors.Finding{
		{Severity: detectors.Critical, Rule: "SECRETS", File: "test.go", Line: 10, Message: "Test message"},
	}
	err := reporter.Report(findings)
	if err == nil {
		t.Error("Expected error when findings exist")
	}
}

func TestJSONReporter_MultipleFindings(t *testing.T) {
	reporter := &JSONReporter{}
	findings := []detectors.Finding{
		{Severity: detectors.Critical, Rule: "SECRETS", File: "test.go", Line: 10, Message: "Test message 1"},
		{Severity: detectors.High, Rule: "AUTH_CREDENTIALS", File: "test.go", Line: 20, Message: "Test message 2"},
		{Severity: detectors.Medium, Rule: "CONFIG_FILE", File: "config.yaml", Line: 5, Message: "Test message 3"},
	}
	err := reporter.Report(findings)
	if err == nil {
		t.Error("Expected error when findings exist")
	}
}
