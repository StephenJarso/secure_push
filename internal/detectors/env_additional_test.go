package detectors

import (
	"testing"
)

func TestEnvDetector_DetectCaseInsensitive(t *testing.T) {
	d := &EnvDetector{}
	tests := []string{".ENV", ".Env.Local", ".ENVRC", "ENV", "Env.Local"}

	for _, filename := range tests {
		t.Run(filename, func(t *testing.T) {
			got, err := d.Detect("content", filename)
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}
			if len(got) == 0 {
				t.Errorf("Detect() returned no findings for %s, want at least 1", filename)
			}
		})
	}
}

func TestEnvDetector_DetectWithPath(t *testing.T) {
	d := &EnvDetector{}
	tests := []struct {
		filename string
		want     int
	}{
		{"/path/to/.env", 1},
		{"/path/to/.env.local", 1},
		{"/path/to/config.go", 0},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			got, err := d.Detect("content", tt.filename)
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}
			if len(got) != tt.want {
				t.Errorf("Detect() returned %d findings, want %d", len(got), tt.want)
			}
		})
	}
}

func TestEnvDetector_FindingMessage(t *testing.T) {
	d := &EnvDetector{}
	got, err := d.Detect("content", ".env")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(got) == 0 {
		t.Fatal("Detect() returned no findings")
	}
	if got[0].Message != ".env file should not be committed" {
		t.Errorf("Message = %q, want .env file should not be committed", got[0].Message)
	}
}
