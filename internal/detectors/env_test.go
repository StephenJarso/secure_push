package detectors

import (
	"testing"
)

func TestEnvDetector_Name(t *testing.T) {
	d := &EnvDetector{}
	if got := d.Name(); got != "ENV_FILE" {
		t.Errorf("Name() = %v, want %v", got, "ENV_FILE")
	}
}

func TestEnvDetector_Severity(t *testing.T) {
	d := &EnvDetector{}
	if got := d.Severity(); got != Critical {
		t.Errorf("Severity() = %v, want %v", got, Critical)
	}
}

func TestEnvDetector_DetectDotEnv(t *testing.T) {
	d := &EnvDetector{}
	tests := []struct {
		filename string
		wantMin  int
	}{
		{".env", 1},
		{".env.local", 1},
		{".env.development", 1},
		{".env.production", 1},
		{".env.test", 1},
		{".envrc", 1},
		{".env.sample", 1},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			got, err := d.Detect("content", tt.filename)
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}
			if len(got) < tt.wantMin {
				t.Errorf("Detect() returned %d findings, want at least %d", len(got), tt.wantMin)
			}
		})
	}
}

func TestEnvDetector_DetectEnvFiles(t *testing.T) {
	d := &EnvDetector{}
	tests := []struct {
		filename string
		wantMin  int
	}{
		{"env", 1},
		{"env.local", 1},
		{"env.development", 1},
		{"env.production", 1},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			got, err := d.Detect("content", tt.filename)
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}
			if len(got) < tt.wantMin {
				t.Errorf("Detect() returned %d findings, want at least %d", len(got), tt.wantMin)
			}
		})
	}
}

func TestEnvDetector_DetectNonEnv(t *testing.T) {
	d := &EnvDetector{}
	tests := []string{"config.go", "main.go", "README.md", "test.txt"}

	for _, filename := range tests {
		t.Run(filename, func(t *testing.T) {
			got, err := d.Detect("content", filename)
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}
			if len(got) != 0 {
				t.Errorf("Detect() returned %d findings, want 0", len(got))
			}
		})
	}
}
