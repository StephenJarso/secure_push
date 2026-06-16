package reporters

import (
	"testing"

	"secure-push/internal/detectors"
)

func TestGitHubReporter_NoFindings(t *testing.T) {
	reporter := &GitHubReporter{}
	err := reporter.Report([]detectors.Finding{})
	if err != nil {
		t.Errorf("Expected no error for empty findings, got: %v", err)
	}
}

func TestGitHubReporter_WithFindings(t *testing.T) {
	reporter := &GitHubReporter{}
	findings := []detectors.Finding{
		{Severity: detectors.Critical, Rule: "SECRETS", File: "test.go", Line: 10, Message: "Test message"},
		{Severity: detectors.High, Rule: "AUTH_CREDENTIALS", File: "test.go", Line: 20, Message: "Test message 2"},
	}
	err := reporter.Report(findings)
	if err == nil {
		t.Error("Expected error when findings exist")
	}
}

func TestGitHubReporter_SeverityMapping(t *testing.T) {
	reporter := &GitHubReporter{}

	tests := []struct {
		severity detectors.Severity
		want     string
	}{
		{detectors.Critical, "error"},
		{detectors.High, "error"},
		{detectors.Medium, "warning"},
		{detectors.Low, "notice"},
	}

	for _, tt := range tests {
		got := reporter.getAnnotationType(tt.severity)
		if got != tt.want {
			t.Errorf("getAnnotationType(%v) = %v, want %v", tt.severity, got, tt.want)
		}
	}
}
