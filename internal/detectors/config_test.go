package detectors

import (
	"testing"
)

func TestConfigDetector(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		content  string
		wantLen  int
	}{
		{"yaml config", "config.yaml", "key: value", 1},
		{"json config", "settings.json", `{"key": "value"}`, 1},
		{"xml config", "app.xml", "<app></app>", 1},
		{"toml config", "config.toml", "[section]\nkey = \"value\"", 1},
		{"ini config", "database.ini", "host=localhost", 1},
		{"properties", "app.properties", "key=value", 1},
		{"regular file", "main.go", "package main", 0},
		{"markdown", "README.md", "# Title", 0},
		{"docker compose", "docker-compose.yml", "services:\n  web:", 1},
		{"Dockerfile", "Dockerfile", "FROM golang:1.21", 1},
		{"Makefile", "Makefile", "build:\n\techo build", 1},
		{"package.json", "package.json", `{"name": "test"}`, 1},
		{"requirements.txt", "requirements.txt", "flask==2.0.0", 1},
		{"Gemfile", "Gemfile", "source 'https://rubygems.org'", 1},
		{"pom.xml", "pom.xml", "<project></project>", 1},
		{"build.gradle", "build.gradle", "plugins {}", 1},
		{"CMakeLists.txt", "CMakeLists.txt", "cmake_minimum_required(VERSION 3.10)", 1},
		{"web.config", "web.config", "<configuration></configuration>", 1},
		{"appsettings", "appsettings.json", `{"Logging": {}}`, 1},
		{"empty yaml", "empty.yaml", "", 1},
		{"empty json", "empty.json", "", 1},
		{"nested config", "nested/config.yaml", "key: value", 1},
		{"config in subdir", "configs/prod/settings.yml", "key: value", 1},
		{"random txt", "notes.txt", "some notes", 0},
		{"go file", "main.go", "package main\n\nfunc main() {}", 0},
		{"python file", "script.py", "print('hello')", 0},
		{"shell script", "deploy.sh", "#!/bin/bash\necho deploy", 0},
		{"gitignore", ".gitignore", "node_modules/", 0},
		{"env file", ".env", "KEY=value", 0},
		{"env example", ".env.example", "KEY=value", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &ConfigDetector{}
			findings, err := d.Detect(tt.content, tt.filename)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(findings) != tt.wantLen {
				t.Errorf("Detect() = %d findings, want %d", len(findings), tt.wantLen)
				for i, f := range findings {
					t.Logf("  Finding %d: %s - %s", i+1, f.Rule, f.Message)
				}
			}
		})
	}
}

func TestConfigDetectorSeverity(t *testing.T) {
	d := &ConfigDetector{}
	if d.Severity() != High {
		t.Errorf("Severity() = %v, want %v", d.Severity(), High)
	}
}

func TestConfigDetectorName(t *testing.T) {
	d := &ConfigDetector{}
	if d.Name() != "CONFIG_FILE" {
		t.Errorf("Name() = %s, want CONFIG_FILE", d.Name())
	}
}

func TestConfigDetectorCaseInsensitive(t *testing.T) {
	d := &ConfigDetector{}

	tests := []struct {
		filename string
		content  string
		wantLen  int
	}{
		{"Config.YAML", "key: value", 1},
		{"SETTINGS.JSON", `{"key": "value"}`, 1},
		{"APP.XML", "<app></app>", 1},
		{"Config.TOML", "[section]", 1},
		{"Database.INI", "host=localhost", 1},
		{"App.Properties", "key=value", 1},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			findings, err := d.Detect(tt.content, tt.filename)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(findings) != tt.wantLen {
				t.Errorf("Detect() = %d findings, want %d for %s", len(findings), tt.wantLen, tt.filename)
			}
		})
	}
}

func TestConfigDetectorEdgeCases(t *testing.T) {
	d := &ConfigDetector{}

	tests := []struct {
		name     string
		filename string
		content  string
		wantLen  int
	}{
		{"empty filename", "", "key: value", 0},
		{"hidden config", ".config.yaml", "key: value", 1},
		{"config with path", "/etc/nginx/nginx.conf", "worker_processes 1;", 1},
		{"no extension config", "Makefile", "build:", 1},
		{"binary-like name", "config.bin", "binary data", 0},
		{"image file", "logo.png", "binary data", 0},
		{"archive file", "backup.tar.gz", "archive data", 0},
		{"compressed file", "data.zip", "compressed data", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := d.Detect(tt.content, tt.filename)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(findings) != tt.wantLen {
				t.Errorf("Detect() = %d findings, want %d", len(findings), tt.wantLen)
			}
		})
	}
}
