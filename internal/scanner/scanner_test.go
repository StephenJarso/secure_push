package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"secure-push/internal/config"
	"secure-push/internal/detectors"
	"secure-push/internal/logger"
)

func TestScanner_ScanEmptyDir(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := config.DefaultConfig()
	log := logger.New(logger.Info)

	detectorList := []detectors.Detector{
		&detectors.EnvDetector{},
		&detectors.SecretsDetector{},
	}

	s := New(detectorList, cfg, log)
	findings, err := s.Scan(tmpDir)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("Scan() returned %d findings, want 0", len(findings))
	}
}

func TestScanner_ScanWithFindings(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.go")
	content := "aws_key = 'AKIAIOSFODNN7EXAMPLE'"
	if err := os.WriteFile(testFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	log := logger.New(logger.Info)

	detectorList := []detectors.Detector{
		&detectors.SecretsDetector{},
	}

	s := New(detectorList, cfg, log)
	findings, err := s.Scan(tmpDir)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("Scan() returned %d findings, want 1", len(findings))
	}
}

func TestScanner_ScanFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test-*.go")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	content := "aws_key = 'AKIAIOSFODNN7EXAMPLE'"
	if err := os.WriteFile(tmpFile.Name(), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	log := logger.New(logger.Info)

	detectorList := []detectors.Detector{
		&detectors.SecretsDetector{},
	}

	s := New(detectorList, cfg, log)
	findings, err := s.ScanFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("ScanFile() returned %d findings, want 1", len(findings))
	}
}

func TestScanner_ScanIgnoredFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.go")
	if err := os.WriteFile(testFile, []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		SeverityThreshold: "medium",
		IgnorePaths:       []string{"*.go"},
		MaxFileSize:       10 * 1024 * 1024,
	}
	log := logger.New(logger.Info)

	detectorList := []detectors.Detector{
		&detectors.SecretsDetector{},
	}

	s := New(detectorList, cfg, log)
	findings, err := s.Scan(tmpDir)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("Scan() returned %d findings, want 0", len(findings))
	}
}
