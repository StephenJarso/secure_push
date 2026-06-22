package reporters

import (
	"os"
	"testing"

	"secure-push/internal/detectors"
)

func TestCSVReporter_SetFile(t *testing.T) {
	reporter := NewCSVReporter("initial.csv")
	reporter.SetFile("changed.csv")

	if reporter.file != "changed.csv" {
		t.Errorf("file = %s, want changed.csv", reporter.file)
	}
}

func TestCSVReporter_FileContent(t *testing.T) {
	tmpFile := t.TempDir() + "/test-content.csv"
	reporter := NewCSVReporter(tmpFile)
	defer os.Remove(tmpFile)

	findings := []detectors.Finding{
		{Severity: detectors.Critical, Rule: "SECRETS", File: "test.go", Line: 10, Message: "Test message"},
	}

	err := reporter.Report(findings)
	if err != nil {
		t.Fatalf("CSVReporter.Report failed: %v", err)
	}

	// Read the file and verify content
	content, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read CSV file: %v", err)
	}

	if len(content) == 0 {
		t.Error("CSV file is empty")
	}
}
