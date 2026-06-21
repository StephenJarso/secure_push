package types

import (
	"testing"
)

func TestFindingCreation(t *testing.T) {
	f := Finding{
		Severity: "high",
		Rule:     "aws-secret-key",
		File:     "config.go",
		Line:     42,
		Message:  "AWS secret key detected",
	}

	if f.Severity != "high" {
		t.Errorf("Expected severity 'high', got %q", f.Severity)
	}
	if f.Rule != "aws-secret-key" {
		t.Errorf("Expected rule 'aws-secret-key', got %q", f.Rule)
	}
	if f.File != "config.go" {
		t.Errorf("Expected file 'config.go', got %q", f.File)
	}
	if f.Line != 42 {
		t.Errorf("Expected line 42, got %d", f.Line)
	}
	if f.Message != "AWS secret key detected" {
		t.Errorf("Expected message 'AWS secret key detected', got %q", f.Message)
	}
}

func TestFindingZeroValues(t *testing.T) {
	f := Finding{}

	if f.Severity != "" {
		t.Errorf("Expected empty severity, got %q", f.Severity)
	}
	if f.Line != 0 {
		t.Errorf("Expected line 0, got %d", f.Line)
	}
}

func TestFindingAllSeverities(t *testing.T) {
	severities := []string{"low", "medium", "high", "critical"}

	for _, s := range severities {
		f := Finding{Severity: s}
		if f.Severity != s {
			t.Errorf("Expected severity %q, got %q", s, f.Severity)
		}
	}
}
