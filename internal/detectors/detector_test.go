package detectors

import (
	"testing"
)

func TestSeverityString(t *testing.T) {
	tests := []struct {
		severity Severity
		expected string
	}{
		{Critical, "CRITICAL"},
		{High, "HIGH"},
		{Medium, "MEDIUM"},
		{Low, "LOW"},
	}

	for _, tt := range tests {
		if got := tt.severity.String(); got != tt.expected {
			t.Errorf("Severity.String() = %q, want %q", got, tt.expected)
		}
	}
}

func TestSeverityIsHigherThan(t *testing.T) {
	tests := []struct {
		s1       Severity
		s2       Severity
		expected bool
	}{
		{High, Medium, true},
		{Medium, High, false},
		{Critical, High, true},
		{Low, Critical, false},
		{Medium, Medium, false},
	}

	for _, tt := range tests {
		if got := tt.s1.IsHigherThan(tt.s2); got != tt.expected {
			t.Errorf("%s.IsHigherThan(%s) = %v, want %v", tt.s1, tt.s2, got, tt.expected)
		}
	}
}

func TestFindingStruct(t *testing.T) {
	f := Finding{
		Severity: High,
		Rule:     "test-rule",
		File:     "test.go",
		Line:     10,
		Message:  "test message",
	}

	if f.Severity != High {
		t.Error("Finding severity not set correctly")
	}
	if f.Rule != "test-rule" {
		t.Error("Finding rule not set correctly")
	}
}
