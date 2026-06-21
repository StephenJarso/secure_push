package config

import (
	"testing"
)

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{"valid config", &Config{SeverityThreshold: "medium", MaxFileSize: 1024}, false},
		{"valid low threshold", &Config{SeverityThreshold: "low", MaxFileSize: 1024}, false},
		{"valid high threshold", &Config{SeverityThreshold: "high", MaxFileSize: 1024}, false},
		{"valid critical threshold", &Config{SeverityThreshold: "critical", MaxFileSize: 1024}, false},
		{"invalid threshold", &Config{SeverityThreshold: "invalid", MaxFileSize: 1024}, true},
		{"zero max file size", &Config{SeverityThreshold: "medium", MaxFileSize: 0}, true},
		{"negative max file size", &Config{SeverityThreshold: "medium", MaxFileSize: -1}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
