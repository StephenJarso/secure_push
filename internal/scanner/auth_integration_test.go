package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"secure-push/internal/config"
	"secure-push/internal/detectors"
	"secure-push/internal/logger"
)

func TestIntegrationScanWithAuthDetector(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.go")
	err := os.WriteFile(configFile, []byte("intercom_token = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	scanner := New([]detectors.Detector{&detectors.AuthDetector{}}, config.DefaultConfig(), logger.New(logger.Debug))
	findings, err := scanner.Scan(tmpDir)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("Scan() returned %d findings, want 1", len(findings))
	}
	if findings[0].Message != "Intercom token found" {
		t.Errorf("Message = %q, want Intercom token found", findings[0].Message)
	}
}

func TestIntegrationScanFileWithAuthDetector(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "config-*.go")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmpFile.WriteString("intercom_token = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'\n"); err != nil {
		t.Fatal(err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatal(err)
	}

	scanner := New([]detectors.Detector{&detectors.AuthDetector{}}, config.DefaultConfig(), logger.New(logger.Debug))
	findings, err := scanner.ScanFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("ScanFile() returned %d findings, want 1", len(findings))
	}
	if findings[0].Line != 1 {
		t.Errorf("Line = %d, want 1", findings[0].Line)
	}
}

func TestIntegrationScanFileSkipsBinaryFile(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "binary-*.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmpFile.Write([]byte{0x00, 0x01, 0x02}); err != nil {
		t.Fatal(err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatal(err)
	}

	scanner := New([]detectors.Detector{&detectors.AuthDetector{}}, config.DefaultConfig(), logger.New(logger.Debug))
	_, err = scanner.ScanFile(tmpFile.Name())
	if err == nil {
		t.Fatal("ScanFile() error = nil, want binary file error")
	}
}

func TestIntegrationScanFileRejectsIgnoredFile(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "config-*.go")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmpFile.WriteString("intercom_token = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'\n"); err != nil {
		t.Fatal(err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		IgnorePaths: []string{tmpFile.Name()},
	}
	scanner := New([]detectors.Detector{&detectors.AuthDetector{}}, cfg, logger.New(logger.Debug))
	_, err = scanner.ScanFile(tmpFile.Name())
	if err == nil {
		t.Fatal("ScanFile() error = nil, want ignored file error")
	}
}
