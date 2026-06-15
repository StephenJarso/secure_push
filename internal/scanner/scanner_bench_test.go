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
	os.WriteFile(testFile, []byte("API_KEY=test123\nDB_PASSWORD=secret\n"), 0o644)

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
	os.WriteFile(testFile, []byte(content), 0o644)

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
	os.WriteFile(testFile, []byte("API_KEY=test123\nDB_PASSWORD=secret\n"), 0o644)

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

func BenchmarkAuthDetector(b *testing.B) {
	d := &detectors.AuthDetector{}
	content := "github_token = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef01234567'\naws_key = 'AKIAIOSFODNN7EXAMPLE'\nslack_token = 'xoxb-1234567890-123456789012-ABCDEFGHIJKLMNO'"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = d.Detect(content, "config.go")
	}
}

func BenchmarkSecretsDetector(b *testing.B) {
	d := &detectors.SecretsDetector{}
	content := "password = 'super_secret_pass123'\napi_key = 'abcdefghijklmnopqrstuvwxyz1234567890'\ntoken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = d.Detect(content, "config.go")
	}
}

func BenchmarkEnvDetector(b *testing.B) {
	d := &detectors.EnvDetector{}
	content := "KEY=value\nDB_PASSWORD=secret\nAPI_KEY=test123"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = d.Detect(content, ".env")
	}
}

func BenchmarkConfigDetector(b *testing.B) {
	d := &detectors.ConfigDetector{}
	content := "key: value\npassword: secret"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = d.Detect(content, "config.yaml")
	}
}
