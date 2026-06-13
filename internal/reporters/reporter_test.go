package reporters

import (
	"bytes"
	"io"
	"os"
	"testing"

	"secure-push/internal/detectors"
)

func TestConsoleReporter(t *testing.T) {
	findings := []detectors.Finding{
		{Severity: detectors.Critical, Rule: "TEST_RULE", File: "test.go", Line: 10, Message: "Test message"},
	}

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	reporter := &ConsoleReporter{}
	_ = reporter.Report(findings)

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)

	if !bytes.Contains(buf.Bytes(), []byte("TEST_RULE")) {
		t.Error("ConsoleReporter did not output rule name")
	}
}

func TestJSONReporter(t *testing.T) {
	findings := []detectors.Finding{
		{Severity: detectors.Critical, Rule: "TEST_RULE", File: "test.go", Line: 10, Message: "Test message"},
	}

	reporter := &JSONReporter{}
	_ = reporter.Report(findings)
}

func TestGitHubReporter(t *testing.T) {
	findings := []detectors.Finding{
		{Severity: detectors.Critical, Rule: "TEST_RULE", File: "test.go", Line: 10, Message: "Test message"},
	}

	reporter := &GitHubReporter{}
	_ = reporter.Report(findings)
}
