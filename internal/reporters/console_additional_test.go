package reporters

import (
	"strings"
	"testing"

	"secure-push/internal/detectors"
)

func TestConsoleReporter_Format(t *testing.T) {
	reporter := &ConsoleReporter{}
	findings := []detectors.Finding{
		{Severity: detectors.Critical, Rule: "SECRETS", File: "test.go", Line: 10, Message: "Test message"},
	}

	got := reporter.Format(findings)

	if !strings.Contains(got, "SECRETS") {
		t.Error("Format() output should contain 'SECRETS'")
	}
	if !strings.Contains(got, "test.go") {
		t.Error("Format() output should contain 'test.go'")
	}
	if !strings.Contains(got, "Test message") {
		t.Error("Format() output should contain 'Test message'")
	}
}

func TestConsoleReporter_FormatEmpty(t *testing.T) {
	reporter := &ConsoleReporter{}
	got := reporter.Format([]detectors.Finding{})

	if !strings.Contains(got, "No sensitive data found") {
		t.Error("Format() output should contain 'No sensitive data found'")
	}
}