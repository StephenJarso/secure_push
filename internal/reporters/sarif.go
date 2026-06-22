package reporters

import (
	"encoding/json"
	"fmt"

	"secure-push/internal/detectors"
)

// SARIFReporter outputs findings in SARIF format for CI/CD integration
type SARIFReporter struct{}

// SARIFReport represents the SARIF format structure
type SARIFReport struct {
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single run in SARIF
type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

// SARIFTool represents the tool information in SARIF
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver represents the tool driver in SARIF
type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules"`
}

// SARIFRule represents a rule in SARIF
type SARIFRule struct {
	ID                   string                    `json:"id"`
	ShortDescription     SARIFShortDescription     `json:"shortDescription"`
	FullDescription      SARIFFullDescription      `json:"fullDescription"`
	DefaultConfiguration SARIFDefaultConfiguration `json:"defaultConfiguration"`
}

// SARIFShortDescription represents a short description in SARIF
type SARIFShortDescription struct {
	Text string `json:"text"`
}

// SARIFFullDescription represents a full description in SARIF
type SARIFFullDescription struct {
	Text string `json:"text"`
}

// SARIFDefaultConfiguration represents default configuration in SARIF
type SARIFDefaultConfiguration struct {
	Level string `json:"level"`
}

// SARIFResult represents a single result in SARIF
type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations"`
}

// SARIFMessage represents a message in SARIF
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation represents a location in SARIF
type SARIFLocation struct {
	ID         int                     `json:"id"`
	URI        string                  `json:"uri"`
	Properties SARIFLocationProperties `json:"properties"`
}

// SARIFLocationProperties represents location properties in SARIF
type SARIFLocationProperties struct {
	Line int `json:"line"`
}

// ToSARIF returns the SARIF JSON string representation of findings
func (r *SARIFReporter) ToSARIF(findings []detectors.Finding) (string, error) {
	rules := make(map[string]bool)
	for _, f := range findings {
		rules[f.Rule] = true
	}

	sarifRules := make([]SARIFRule, 0, len(rules))
	for ruleID := range rules {
		sarifRules = append(sarifRules, SARIFRule{
			ID: ruleID,
			ShortDescription: SARIFShortDescription{
				Text: ruleID + " security issue detected",
			},
			FullDescription: SARIFFullDescription{
				Text: "Security issue detected by Secure Push scanner",
			},
			DefaultConfiguration: SARIFDefaultConfiguration{
				Level: "error",
			},
		})
	}

	results := make([]SARIFResult, 0, len(findings))
	for i, f := range findings {
		results = append(results, SARIFResult{
			RuleID: f.Rule,
			Message: SARIFMessage{
				Text: f.Message,
			},
			Locations: []SARIFLocation{
				{
					ID:  i + 1,
					URI: f.File,
					Properties: SARIFLocationProperties{
						Line: f.Line,
					},
				},
			},
		})
	}

	report := SARIFReport{
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "Secure Push",
						Version:        "0.1.0",
						InformationURI: "https://github.com/secure-push/secure-push",
						Rules:          sarifRules,
					},
				},
				Results: results,
			},
		},
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal SARIF report: %w", err)
	}

	return string(data), nil
}

// Report outputs findings in SARIF format
func (r *SARIFReporter) Report(findings []detectors.Finding) error {
	data, err := r.ToSARIF(findings)
	if err != nil {
		return err
	}

	fmt.Println(data)

	if len(findings) > 0 {
		return fmt.Errorf("scan found %d security issues", len(findings))
	}

	return nil
}
