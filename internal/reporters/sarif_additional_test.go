package reporters

import (
	"strings"
	"testing"

	"secure-push/internal/detectors"
)

func TestSARIFReporter_ToSARIF(t *testing.T) {
	reporter := &SARIFReporter{}
	findings := []detectors.Finding{
		{Severity: detectors.Critical, Rule: "SECRETS", File: "test.go", Line: 10, Message: "Test message"},
	}

	got, err := reporter.ToSARIF(findings)
	if err != nil {
		t.Fatalf("ToSARIF() error = %v", err)
	}

	if !strings.Contains(got, "SECRETS") {
		t.Error("ToSARIF() output should contain 'SECRETS'")
	}
	if !strings.Contains(got, "test.go") {
		t.Error("ToSARIF() output should contain 'test.go'")
	}
	if !strings.Contains(got, "2.1.0") {
		t.Error("ToSARIF() output should contain version 2.1.0")
	}
}

func TestSARIFReporter_ToSARIFEmpty(t *testing.T) {
	reporter := &SARIFReporter{}
	got, err := reporter.ToSARIF([]detectors.Finding{})
	if err != nil {
		t.Fatalf("ToSARIF() error = %v", err)
	}

	if !strings.Contains(got, `"version"`) {
		t.Error("ToSARIF() output should be valid JSON with version")
	}
}
