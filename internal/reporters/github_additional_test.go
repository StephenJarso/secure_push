package reporters

import (
	"strings"
	"testing"

	"secure-push/internal/detectors"
)

func TestGitHubReporter_ToAnnotations(t *testing.T) {
	reporter := &GitHubReporter{}
	findings := []detectors.Finding{
		{Severity: detectors.Critical, Rule: "SECRETS", File: "test.go", Line: 10, Message: "Test message"},
	}

	got := reporter.ToAnnotations(findings)
	if len(got) != 1 {
		t.Errorf("ToAnnotations() returned %d annotations, want 1", len(got))
	}

	if !strings.Contains(got[0], "::error") {
		t.Error("ToAnnotations() should contain error annotation for critical severity")
	}
	if !strings.Contains(got[0], "test.go") {
		t.Error("ToAnnotations() should contain file name")
	}
}

func TestGitHubReporter_ToAnnotationsEmpty(t *testing.T) {
	reporter := &GitHubReporter{}
	got := reporter.ToAnnotations([]detectors.Finding{})
	if len(got) != 0 {
		t.Errorf("ToAnnotations() returned %d annotations, want 0", len(got))
	}
}
