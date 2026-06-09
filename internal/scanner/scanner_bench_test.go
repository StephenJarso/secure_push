package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"secure-push/internal/config"
	"secure-push/internal/detectors"
	"secure-push/internal/logger"
)

func BenchmarkScanSmallFile(b *testing.B) {
	tmpDir := b.TempDir()
	testFile := filepath.Join(tmpDir, "test.env")
	os.WriteFile(testFile, []byte("API_KEY=test123\nDB_PASSWORD=secret\n"), 0644)

	cfg := config.DefaultConfig()
	log := logger.New(logger.Debug)
	scanner := New([]detectors.Detector{&detectors.EnvDetector{}}, cfg, log)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = scanner.ScanFile(testFile)
	}
}

func BenchmarkScanLargeFile(b *testing.B) {
	tmpDir := b.TempDir()
	testFile := filepath.Join(tmpDir, "large.env")
	content := ""
	for i := 0; i < 1000; i++ {
		content += "API_KEY_" + string(rune(i)) + "=test123\n"
	}
	os.WriteFile(testFile, []byte(content), 0644)

	cfg := config.DefaultConfig()
	log := logger.New(logger.Debug)
	scanner := New([]detectors.Detector{&detectors.EnvDetector{}}, cfg, log)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = scanner.ScanFile(testFile)
	}
}

func BenchmarkScanMultipleDetectors(b *testing.B) {
	tmpDir := b.TempDir()
	testFile := filepath.Join(tmpDir, "test.env")
	os.WriteFile(testFile, []byte("API_KEY=test123\nDB_PASSWORD=secret\n"), 0644)

	cfg := config.DefaultConfig()
	log := logger.New(logger.Debug)
	scanner := New(
		[]detectors.Detector{
			&detectors.EnvDetector{},
			&detectors.SecretsDetector{},
			&detectors.AuthDetector{},
		},
		cfg,
		log,
	)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = scanner.ScanFile(testFile)
	}
}
