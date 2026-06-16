package reporters

import (
	"testing"

	"secure-push/internal/detectors"
)

func TestSummaryReporter(t *testing.T) {
	findings := []detectors.Finding{
		{Severity: detectors.Critical, Rule: "SECRETS", File: "test.go", Line: 10, Message: "Test message"},
		{Severity: detectors.High, Rule: "AUTH_CREDENTIALS", File: "test.go", Line: 20, Message: "Test message 2"},
		{Severity: detectors.Medium, Rule: "SECRETS", File: "other.go", Line: 5, Message: "Test message 3"},
	}

	reporter := &SummaryReporter{}
	err := reporter.Report(findings)
	if err == nil {
		t.Error("Expected error when findings exist")
	}
}

func TestSummaryReporter_NoFindings(t *testing.T) {
	reporter := &SummaryReporter{}
	err := reporter.Report([]detectors.Finding{})
	if err != nil {
		t.Errorf("Expected no error for empty findings, got: %v", err)
	}
}
