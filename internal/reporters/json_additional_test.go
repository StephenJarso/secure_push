package reporters

import (
	"strings"
	"testing"

	"secure-push/internal/detectors"
)

func TestJSONReporter_ToJSON(t *testing.T) {
	reporter := &JSONReporter{}
	findings := []detectors.Finding{
		{Severity: detectors.Critical, Rule: "SECRETS", File: "test.go", Line: 10, Message: "Test message"},
	}

	got, err := reporter.ToJSON(findings)
	if err != nil {
		t.Fatalf("ToJSON() error = %v", err)
	}

	if !strings.Contains(got, "SECRETS") {
		t.Error("ToJSON() output should contain 'SECRETS'")
	}
	if !strings.Contains(got, "test.go") {
		t.Error("ToJSON() output should contain 'test.go'")
	}
}

func TestJSONReporter_ToJSONEmpty(t *testing.T) {
	reporter := &JSONReporter{}
	got, err := reporter.ToJSON([]detectors.Finding{})
	if err != nil {
		t.Fatalf("ToJSON() error = %v", err)
	}

	if !strings.Contains(got, `"total": 0`) {
		t.Error("ToJSON() output should contain total: 0")
	}
}
