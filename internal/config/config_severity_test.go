package config

import (
	"testing"

	"secure-push/internal/detectors"
)

func TestIsSeverityEnabled_AllThresholds(t *testing.T) {
	tests := []struct {
		threshold string
		severity  detectors.Severity
		want      bool
	}{
		{"low", detectors.Low, true},
		{"low", detectors.Medium, true},
		{"low", detectors.High, true},
		{"low", detectors.Critical, true},
		{"medium", detectors.Low, false},
		{"medium", detectors.Medium, true},
		{"medium", detectors.High, true},
		{"medium", detectors.Critical, true},
		{"high", detectors.Low, false},
		{"high", detectors.Medium, false},
		{"high", detectors.High, true},
		{"high", detectors.Critical, true},
		{"critical", detectors.Low, false},
		{"critical", detectors.Medium, false},
		{"critical", detectors.High, false},
		{"critical", detectors.Critical, true},
		{"unknown", detectors.Critical, true},
	}

	for _, tt := range tests {
		cfg := &Config{SeverityThreshold: tt.threshold}
		got := cfg.IsSeverityEnabled(tt.severity)
		if got != tt.want {
			t.Errorf("IsSeverityEnabled(%q, %v) = %v, want %v", tt.threshold, tt.severity, got, tt.want)
		}
	}
}
