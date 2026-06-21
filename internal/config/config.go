package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"secure-push/internal/detectors"

	"github.com/bmatcuk/doublestar/v4"
)

// CustomRule represents a user-defined rule
type CustomRule struct {
	Path     string             `yaml:"path"`
	Severity detectors.Severity `yaml:"severity"`
}

type Config struct {
	SeverityThreshold string       `yaml:"severity_threshold"`
	IgnoreRules       []string     `yaml:"ignore_rules"`
	IgnorePaths       []string     `yaml:"ignore_paths"`
	Allowlist         []string     `yaml:"allowlist"`
	CustomRules       []CustomRule `yaml:"custom_rules"`
	CustomRuleFiles   []string     `yaml:"custom_rule_files"`
	MaxFileSize       int64        `yaml:"max_file_size"`
	EnableDetectors   []string     `yaml:"enable_detectors"`
	DisableDetectors  []string     `yaml:"disable_detectors"`
	ExitCode          int          `yaml:"exit_code"`
}

func DefaultConfig() *Config {
	return &Config{
		SeverityThreshold: "medium",
		IgnoreRules:       []string{},
		IgnorePaths:       []string{},
		Allowlist:         []string{},
		CustomRules:       []CustomRule{},
		CustomRuleFiles:   []string{},
		MaxFileSize:       10 * 1024 * 1024,
		EnableDetectors:   []string{},
		DisableDetectors:  []string{},
		ExitCode:          1,
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
		// Return default config if file doesn't exist
		if os.IsNotExist(err) {
			return cfg, nil
		}
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

	for _, p := range possiblePaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	return ""
}

func (c *Config) ShouldIgnore(path string) bool {
	// Check allowlist first - if file is in allowlist, don't ignore it
	for _, allowed := range c.Allowlist {
		if matchPath(allowed, path) {
			return false
		}
	}

	// Check ignore paths
	for _, ignorePath := range c.IgnorePaths {
		if matchPath(ignorePath, path) {
			return true
		}
	}

	return false
}

// matchPath handles both simple patterns and glob patterns including **
func matchPath(pattern, targetPath string) bool {
	// Try doublestar for ** support
	matched, err := doublestar.Match(pattern, targetPath)
	if err == nil && matched {
		return true
	}

	// Try matching just the base name
	matched, err = doublestar.Match(pattern, filepath.Base(targetPath))
	if err == nil && matched {
		return true
	}

	// Check if path contains the pattern (for directory matching)
	if strings.Contains(targetPath, pattern) {
		return true
	}

	// Check if path starts with pattern (for directory prefix matching)
	if strings.HasPrefix(targetPath, pattern) {
		return true
	}

	return false
}

func (c *Config) IsSeverityEnabled(severity detectors.Severity) bool {
	switch c.SeverityThreshold {
	case "low":
		return true
	case "medium":
		return severity != detectors.Low
	case "high":
		return severity == detectors.High || severity == detectors.Critical
	case "critical":
		return severity == detectors.Critical
	default:
		return true
	}
}

func (c *Config) IsDetectorEnabled(detectorName string) bool {
	// Check if detector is in ignore_rules
	for _, ignored := range c.IgnoreRules {
		if strings.EqualFold(ignored, detectorName) {
			return false
		}
	}

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
