package reporters

import (
	"encoding/json"
	"fmt"
	"os"

	"secure-push/internal/detectors"
)

type JSONReporter struct{}

type JSONReport struct {
	Total   int                `json:"total"`
	Findings []detectors.Finding `json:"findings"`
}

func (r *JSONReporter) Report(findings []detectors.Finding) error {
	report := JSONReport{
		Total:    len(findings),
		Findings: findings,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}

	fmt.Println(string(data))

	if len(findings) > 0 {
		os.Exit(1)
	}

	return nil
}
