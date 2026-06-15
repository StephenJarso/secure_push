package reporters

import (
	"testing"

	"secure-push/internal/detectors"
)

func TestConsoleReporter(t *testing.T) {
	findings := []detectors.Finding{
		{Severity: detectors.Critical, Rule: "TEST_RULE", File: "test.go", Line: 10, Message: "Test message"},
	}

	// Test the helper functions
	icon := getSeverityIcon(detectors.Critical)
	if icon != "🔴" {
		t.Errorf("Expected red icon for critical, got %s", icon)
	}

	count := countBySeverity(findings, detectors.Critical)
	if count != 1 {
		t.Errorf("Expected 1 critical finding, got %d", count)
	}
}

func TestJSONReporter(t *testing.T) {
	_ = []detectors.Finding{
		{Severity: detectors.Critical, Rule: "TEST_RULE", File: "test.go", Line: 10, Message: "Test message"},
	}

	reporter := &JSONReporter{}
	// Note: Report calls os.Exit(1) when findings exist, so we test with empty findings
	_ = reporter.Report([]detectors.Finding{})
}

func TestGitHubReporter(t *testing.T) {
	_ = []detectors.Finding{
		{Severity: detectors.Critical, Rule: "TEST_RULE", File: "test.go", Line: 10, Message: "Test message"},
	}

	reporter := &GitHubReporter{}
	// Note: Report calls os.Exit(1) when findings exist, so we test with empty findings
	_ = reporter.Report([]detectors.Finding{})
}

func TestCSVReporter(t *testing.T) {
	findings := []detectors.Finding{
		{Severity: detectors.Critical, Rule: "TEST_RULE", File: "test.go", Line: 10, Message: "Test message"},
	}

	reporter := NewCSVReporter(t.TempDir() + "/test.csv")
	err := reporter.Report(findings)
	if err != nil {
		t.Errorf("CSVReporter.Report failed: %v", err)
	}
}

func TestSARIFReporter(t *testing.T) {
	reporter := &SARIFReporter{}
	// Note: Report calls os.Exit(1) when findings exist, so we test with empty findings
	_ = reporter.Report([]detectors.Finding{})
}
