package reporters

import (
	"os"
	"testing"

	"secure-push/internal/detectors"
)

func TestCSVReporter_NoFindings(t *testing.T) {
	tmpFile := t.TempDir() + "/test-empty.csv"
	reporter := NewCSVReporter(tmpFile)
	defer os.Remove(tmpFile)

	err := reporter.Report([]detectors.Finding{})
	if err != nil {
		t.Errorf("CSVReporter.Report failed: %v", err)
	}
}

func TestCSVReporter_MultipleFindings(t *testing.T) {
	tmpFile := t.TempDir() + "/test-multi.csv"
	reporter := NewCSVReporter(tmpFile)
	defer os.Remove(tmpFile)

	findings := []detectors.Finding{
		{Severity: detectors.Critical, Rule: "SECRETS", File: "test.go", Line: 10, Message: "Test message 1"},
		{Severity: detectors.High, Rule: "AUTH_CREDENTIALS", File: "test.go", Line: 20, Message: "Test message 2"},
		{Severity: detectors.Medium, Rule: "CONFIG_FILE", File: "config.yaml", Line: 5, Message: "Test message 3"},
	}

	err := reporter.Report(findings)
	if err != nil {
		t.Errorf("CSVReporter.Report failed: %v", err)
	}
}
