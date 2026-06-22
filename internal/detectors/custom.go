package detectors

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// CustomRuleConfig represents a rule loaded from a YAML file
type CustomRuleConfig struct {
	Name        string `yaml:"name"`
	Pattern     string `yaml:"pattern"`
	Severity    string `yaml:"severity"`
	Message     string `yaml:"message"`
	Description string `yaml:"description"`
}

// CustomRuleDetector loads and applies custom rules from YAML files
type CustomRuleDetector struct {
	rules []CustomRuleConfig
}

func (d *CustomRuleDetector) Name() string {
	return "CUSTOM_RULE"
}

func (d *CustomRuleDetector) Severity() Severity {
	return Medium
}

// LoadRules loads custom rules from a YAML file
func (d *CustomRuleDetector) LoadRules(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read custom rules file: %w", err)
	}

	var rules []CustomRuleConfig
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return fmt.Errorf("failed to parse custom rules file: %w", err)
	}

	d.rules = rules
	return nil
}

// AddRule adds a custom rule programmatically
func (d *CustomRuleDetector) AddRule(rule CustomRuleConfig) error {
	// Validate the pattern compiles
	_, err := regexp.Compile(rule.Pattern)
	if err != nil {
		return fmt.Errorf("invalid regex pattern: %w", err)
	}

	d.rules = append(d.rules, rule)
	return nil
}

// Detect applies custom rules to content
func (d *CustomRuleDetector) Detect(content string, filename string) ([]Finding, error) {
	var findings []Finding
	lines := strings.Split(content, "\n")

	for _, rule := range d.rules {
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			// Skip invalid regex patterns
			continue
		}

		severity := parseSeverity(rule.Severity)
		if severity == "" {
			severity = Medium
		}

		for lineNum, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			if re.MatchString(line) {
				message := rule.Message
				if message == "" {
					message = fmt.Sprintf("Custom rule '%s' matched", rule.Name)
				}

				findings = append(findings, Finding{
					Rule:     d.Name(),
					Severity: severity,
					File:     filename,
					Line:     lineNum + 1,
					Message:  message,
				})
			}
		}
	}

	return findings, nil
}

func parseSeverity(severity string) Severity {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return Critical
	case "HIGH":
		return High
	case "MEDIUM":
		return Medium
	case "LOW":
		return Low
	default:
		return ""
	}
}

// RuleCount returns the number of loaded custom rules
func (d *CustomRuleDetector) RuleCount() int {
	return len(d.rules)
}
