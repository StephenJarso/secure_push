package reporters

import (
	"testing"

	"secure-push/internal/detectors"
)

func TestConsoleReporterNoFindings(t *testing.T) {
	reporter := &ConsoleReporter{}
	err := reporter.Report([]detectors.Finding{})
	if err != nil {
		t.Errorf("Expected no error for empty findings, got: %v", err)
	}
}

func TestConsoleReporter_WithFindings(t *testing.T) {
	reporter := &ConsoleReporter{}
	findings := []detectors.Finding{
		{Severity: detectors.Critical, Rule: "SECRETS", File: "test.go", Line: 10, Message: "Test message"},
		{Severity: detectors.High, Rule: "AUTH_CREDENTIALS", File: "test.go", Line: 20, Message: "Test message 2"},
	}
	err := reporter.Report(findings)
	if err == nil {
		t.Error("Expected error when findings exist")
	}
}

func TestGetSeverityIcon(t *testing.T) {
	tests := []struct {
		severity detectors.Severity
		want     string
	}{
		{detectors.Critical, "🔴"},
		{detectors.High, "🟠"},
		{detectors.Medium, "🟡"},
		{detectors.Low, "🔵"},
		{"UNKNOWN", "⚪"},
	}

	for _, tt := range tests {
		got := getSeverityIcon(tt.severity)
		if got != tt.want {
			t.Errorf("getSeverityIcon(%v) = %v, want %v", tt.severity, got, tt.want)
		}
	}
}

func TestCountBySeverity(t *testing.T) {
	findings := []detectors.Finding{
		{Severity: detectors.Critical, Rule: "SECRETS", File: "test.go", Line: 10, Message: "Test"},
		{Severity: detectors.High, Rule: "AUTH", File: "test.go", Line: 20, Message: "Test"},
		{Severity: detectors.Critical, Rule: "SECRETS", File: "test.go", Line: 30, Message: "Test"},
	}

	if count := countBySeverity(findings, detectors.Critical); count != 2 {
		t.Errorf("countBySeverity(Critical) = %d, want 2", count)
	}
	if count := countBySeverity(findings, detectors.High); count != 1 {
		t.Errorf("countBySeverity(High) = %d, want 1", count)
	}
	if count := countBySeverity(findings, detectors.Medium); count != 0 {
		t.Errorf("countBySeverity(Medium) = %d, want 0", count)
	}
}
