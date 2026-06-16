package detectors

import (
	"testing"
)

func TestConfigDetector_Name(t *testing.T) {
	d := &ConfigDetector{}
	if got := d.Name(); got != "CONFIG_FILE" {
		t.Errorf("Name() = %v, want %v", got, "CONFIG_FILE")
	}
}

func TestConfigDetector_Severity(t *testing.T) {
	d := &ConfigDetector{}
	if got := d.Severity(); got != High {
		t.Errorf("Severity() = %v, want %v", got, High)
	}
}

func TestConfigDetector_DetectDotEnv(t *testing.T) {
	d := &ConfigDetector{}
	got, err := d.Detect("content", ".env")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(got) != 1 {
		t.Errorf("Detect() returned %d findings, want 1", len(got))
	}
}

func TestConfigDetector_DetectYaml(t *testing.T) {
	d := &ConfigDetector{}
	got, err := d.Detect("content", "config.yaml")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(got) != 1 {
		t.Errorf("Detect() returned %d findings, want 1", len(got))
	}
}

func TestConfigDetector_DetectJson(t *testing.T) {
	d := &ConfigDetector{}
	got, err := d.Detect("content", "package.json")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(got) != 1 {
		t.Errorf("Detect() returned %d findings, want 1", len(got))
	}
}

func TestConfigDetector_DetectDockerfile(t *testing.T) {
	d := &ConfigDetector{}
	got, err := d.Detect("content", "Dockerfile")
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(got) != 1 {
		t.Errorf("Detect() returned %d findings, want 1", len(got))
	}
}

func TestConfigDetector_DetectNonConfig(t *testing.T) {
	d := &ConfigDetector{}
	tests := []string{"main.go", "README.md", "test.txt"}

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
