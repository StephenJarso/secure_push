package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"secure-push/internal/config"
	"secure-push/internal/detectors"
	"secure-push/internal/logger"
)

func TestParallelScan(t *testing.T) {
	tmpDir := t.TempDir()
	for i := 0; i < 5; i++ {
		testFile := filepath.Join(tmpDir, "test.go")
		content := "password = 'secret123'"
		if err := os.WriteFile(testFile, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Create additional files to test parallel scanning
	for i := 0; i < 4; i++ {
		testFile := filepath.Join(tmpDir, "test2.go")
		content := "api_key = 'abcdefghijklmnopqrstuvwxyz1234567890'"
		if err := os.WriteFile(testFile, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Create unique files
	for i := 0; i < 3; i++ {
		testFile := filepath.Join(tmpDir, "test3.go")
		content := "aws_key = 'AKIAIOSFODNN7EXAMPLE'"
		if err := os.WriteFile(testFile, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
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
	if len(findings) != 5 {
		t.Errorf("Scan() returned %d findings, want 5", len(findings))
	}
}

func TestParallelScanWithErrors(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.go")
	if err := os.WriteFile(testFile, []byte("test"), 0o644); err != nil {
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
	if len(findings) != 0 {
		t.Errorf("Scan() returned %d findings, want 0", len(findings))
	}
}
