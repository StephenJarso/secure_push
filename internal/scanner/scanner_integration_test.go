package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"secure-push/internal/config"
	"secure-push/internal/detectors"
	"secure-push/internal/logger"
)

func TestIntegrationScanWithEnvFiles(t *testing.T) {
	tmpDir := t.TempDir()

	envFile := filepath.Join(tmpDir, ".env")
	os.WriteFile(envFile, []byte("API_KEY=secret123\nDB_PASSWORD=pass\n"), 0o644)

	regularFile := filepath.Join(tmpDir, "main.go")
	os.WriteFile(regularFile, []byte("package main\n\nfunc main() {}\n"), 0o644)

	cfg := config.DefaultConfig()
	log := logger.New(logger.Debug)
	scanner := New([]detectors.Detector{&detectors.EnvDetector{}}, cfg, log)

	findings, err := scanner.Scan(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(findings))
	}
}

func TestIntegrationScanWithSecrets(t *testing.T) {
	tmpDir := t.TempDir()

	secretFile := filepath.Join(tmpDir, "config.go")
	os.WriteFile(secretFile, []byte("const API_KEY = \"ghp_1234567890abcdefghijklmnopqrstuvwxyz\"\n"), 0o644)

	cfg := config.DefaultConfig()
	log := logger.New(logger.Debug)
	scanner := New([]detectors.Detector{&detectors.SecretsDetector{}}, cfg, log)

	findings, err := scanner.Scan(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(findings))
	}
}

func TestIntegrationScanWithConfig(t *testing.T) {
	tmpDir := t.TempDir()

	configFile := filepath.Join(tmpDir, "config.yaml")
	os.WriteFile(configFile, []byte("database:\n  host: localhost\n  password: secret\n"), 0o644)

	cfg := config.DefaultConfig()
	log := logger.New(logger.Debug)
	scanner := New([]detectors.Detector{&detectors.ConfigDetector{}}, cfg, log)

	findings, err := scanner.Scan(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(findings))
	}
}

func TestIntegrationScanWithIgnorePatterns(t *testing.T) {
	tmpDir := t.TempDir()

	envFile := filepath.Join(tmpDir, ".env")
	os.WriteFile(envFile, []byte("API_KEY=secret123\n"), 0o644)

	ignoredFile := filepath.Join(tmpDir, "vendor", "lib", "config.env")
	os.MkdirAll(filepath.Join(tmpDir, "vendor", "lib"), 0o755)
	os.WriteFile(ignoredFile, []byte("API_KEY=secret456\n"), 0o644)

	cfg := config.DefaultConfig()
	log := logger.New(logger.Debug)
	scanner := New([]detectors.Detector{&detectors.EnvDetector{}}, cfg, log)

	findings, err := scanner.Scan(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Errorf("Expected 1 finding (ignored file should be skipped), got %d", len(findings))
	}
}

func TestIntegrationScanWithBinaryFiles(t *testing.T) {
	tmpDir := t.TempDir()

	textFile := filepath.Join(tmpDir, "readme.txt")
	os.WriteFile(textFile, []byte("This is a text file\n"), 0o644)

	binaryFile := filepath.Join(tmpDir, "image.png")
	os.WriteFile(binaryFile, []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, 0o644)

	cfg := config.DefaultConfig()
	log := logger.New(logger.Debug)
	scanner := New([]detectors.Detector{&detectors.EnvDetector{}}, cfg, log)

	findings, err := scanner.Scan(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings (binary file should be skipped), got %d", len(findings))
	}
}

func TestIntegrationScanWithLargeFiles(t *testing.T) {
	tmpDir := t.TempDir()

	largeFile := filepath.Join(tmpDir, "large.env")
	content := ""
	for i := 0; i < 10000; i++ {
		content += "API_KEY_" + string(rune(i)) + "=test123\n"
	}
	os.WriteFile(largeFile, []byte(content), 0o644)

	cfg := &config.Config{
		MaxFileSize: 100,
	}
	log := logger.New(logger.Debug)
	scanner := New([]detectors.Detector{&detectors.EnvDetector{}}, cfg, log)

	findings, err := scanner.Scan(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings (large file should be skipped), got %d", len(findings))
	}
}

func TestIntegrationScanWithMultipleDetectors(t *testing.T) {
	tmpDir := t.TempDir()

	envFile := filepath.Join(tmpDir, ".env")
	os.WriteFile(envFile, []byte("API_KEY=secret123\n"), 0o644)

	secretFile := filepath.Join(tmpDir, "config.go")
	os.WriteFile(secretFile, []byte("const API_KEY = \"ghp_1234567890abcdefghijklmnopqrstuvwxyz\"\n"), 0o644)

	configFile := filepath.Join(tmpDir, "config.yaml")
	os.WriteFile(configFile, []byte("database:\n  host: localhost\n"), 0o644)

	cfg := config.DefaultConfig()
	log := logger.New(logger.Debug)
	scanner := New(
		[]detectors.Detector{
			&detectors.EnvDetector{},
			&detectors.SecretsDetector{},
			&detectors.ConfigDetector{},
		},
		cfg,
		log,
	)

	findings, err := scanner.Scan(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 4 findings: .env (ENV_FILE + CONFIG_FILE), config.go (SECRETS), config.yaml (CONFIG_FILE)
	if len(findings) != 4 {
		t.Errorf("Expected 4 findings, got %d", len(findings))
	}
}

func TestIntegrationScanWithDisabledDetector(t *testing.T) {
	tmpDir := t.TempDir()

	envFile := filepath.Join(tmpDir, ".env")
	os.WriteFile(envFile, []byte("API_KEY=secret123\n"), 0o644)

	cfg := &config.Config{
		DisableDetectors: []string{"ENV_FILE"},
	}
	log := logger.New(logger.Debug)
	scanner := New([]detectors.Detector{&detectors.EnvDetector{}}, cfg, log)

	findings, err := scanner.Scan(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings (detector disabled), got %d", len(findings))
	}
}

func TestIntegrationScanWithSeverityFilter(t *testing.T) {
	tmpDir := t.TempDir()

	envFile := filepath.Join(tmpDir, ".env")
	os.WriteFile(envFile, []byte("API_KEY=secret123\n"), 0o644)

	cfg := &config.Config{
		SeverityThreshold: "critical",
	}
	log := logger.New(logger.Debug)
	scanner := New([]detectors.Detector{&detectors.EnvDetector{}}, cfg, log)

	findings, err := scanner.Scan(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings (severity filter), got %d", len(findings))
	}
}

func TestIntegrationScanNestedDirectories(t *testing.T) {
	tmpDir := t.TempDir()

	nestedDir := filepath.Join(tmpDir, "src", "api", "config")
	os.MkdirAll(nestedDir, 0o755)

	envFile := filepath.Join(nestedDir, ".env")
	os.WriteFile(envFile, []byte("API_KEY=secret123\n"), 0o644)

	regularFile := filepath.Join(tmpDir, "src", "main.go")
	os.WriteFile(regularFile, []byte("package main\n\nfunc main() {}\n"), 0o644)

	cfg := config.DefaultConfig()
	log := logger.New(logger.Debug)
	scanner := New([]detectors.Detector{&detectors.EnvDetector{}}, cfg, log)

	findings, err := scanner.Scan(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(findings))
	}
}

func TestIntegrationScanEmptyDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := config.DefaultConfig()
	log := logger.New(logger.Debug)
	scanner := New([]detectors.Detector{&detectors.EnvDetector{}}, cfg, log)

	findings, err := scanner.Scan(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings in empty directory, got %d", len(findings))
	}
}
