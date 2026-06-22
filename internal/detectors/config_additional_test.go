package detectors

import (
	"testing"
)

func TestConfigDetector_DetectAllExtensions(t *testing.T) {
	d := &ConfigDetector{}
	tests := []string{
		"config.yaml", "config.yml", "config.json", "config.xml",
		"config.toml", "config.ini", "config.cfg", "config.conf",
		"config.properties", "config.envrc",
	}

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

func TestConfigDetector_DetectAllFilenames(t *testing.T) {
	d := &ConfigDetector{}
	tests := []string{
		"config", "configuration", "settings",
		"application", "appsettings", "package.json",
		"requirements.txt", "gemfile", "dockerfile",
	}

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

func TestConfigDetector_DetectNonConfigFiles(t *testing.T) {
	d := &ConfigDetector{}
	tests := []string{"main.go", "index.js", "README.md", "test.txt"}

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
