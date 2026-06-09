package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	IgnorePatterns  []string `yaml:"ignore_patterns"`
	IgnoreFiles     []string `yaml:"ignore_files"`
	MaxFileSize     int64    `yaml:"max_file_size"`
	Severity        string   `yaml:"severity"`
	EnableDetectors []string `yaml:"enable_detectors"`
	DisableDetectors []string `yaml:"disable_detectors"`
}

func DefaultConfig() *Config {
	return &Config{
		IgnorePatterns:  []string{},
		IgnoreFiles:     []string{".git/**", "vendor/**", "node_modules/**"},
		MaxFileSize:     10 * 1024 * 1024,
		Severity:        "medium",
		EnableDetectors: []string{},
		DisableDetectors: []string{},
	}
}

func Load(configPath string) (*Config, error) {
	cfg := DefaultConfig()

	if configPath == "" {
		configPath = findConfigFile()
	}

	if configPath == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return cfg, nil
}

func findConfigFile() string {
	possiblePaths := []string{
		".secure-push.yaml",
		".secure-push.yml",
		".secure-push.json",
	}

	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

func (c *Config) ShouldIgnore(path string) bool {
	base := filepath.Base(path)

	for _, ignoreFile := range c.IgnoreFiles {
		matched, err := filepath.Match(ignoreFile, base)
		if err == nil && matched {
			return true
		}

		matched, err = filepath.Match(ignoreFile, path)
		if err == nil && matched {
			return true
		}
	}

	for _, pattern := range c.IgnorePatterns {
		matched, err := filepath.Match(pattern, path)
		if err == nil && matched {
			return true
		}
	}

	return false
}

func (c *Config) IsSeverityEnabled(severity Severity) bool {
	switch c.Severity {
	case "low":
		return true
	case "medium":
		return severity != Low
	case "high":
		return severity == High || severity == Critical
	case "critical":
		return severity == Critical
	default:
		return true
	}
}

func (c *Config) IsDetectorEnabled(detectorName string) bool {
	if len(c.EnableDetectors) > 0 {
		for _, enabled := range c.EnableDetectors {
			if strings.EqualFold(enabled, detectorName) {
				return true
			}
		}
		return false
	}

	for _, disabled := range c.DisableDetectors {
		if strings.EqualFold(disabled, detectorName) {
			return false
		}
	}

	return true
}
