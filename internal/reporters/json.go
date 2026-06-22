package reporters

import (
	"encoding/json"
	"fmt"

	"secure-push/internal/detectors"
)

type JSONReporter struct{}

type JSONReport struct {
	Total    int                 `json:"total"`
	Findings []detectors.Finding `json:"findings"`
}

// ToJSON returns the JSON representation of the report
func (r *JSONReporter) ToJSON(findings []detectors.Finding) (string, error) {
	report := JSONReport{
		Total:    len(findings),
		Findings: findings,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal report: %w", err)
	}

	return string(data), nil
}

func (r *JSONReporter) Report(findings []detectors.Finding) error {
	data, err := r.ToJSON(findings)
	if err != nil {
		return err
	}

	fmt.Println(data)

	if len(findings) > 0 {
		return fmt.Errorf("scan found %d security issues", len(findings))
	}

	return nil
}
