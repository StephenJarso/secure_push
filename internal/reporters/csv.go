package reporters

import (
	"encoding/csv"
	"fmt"
	"os"

	"secure-push/internal/detectors"
)

// CSVReporter outputs findings in CSV format
type CSVReporter struct {
	file string
}

// NewCSVReporter creates a new CSV reporter
func NewCSVReporter(file string) *CSVReporter {
	return &CSVReporter{file: file}
}

// SetFile changes the output file for the CSV reporter
func (r *CSVReporter) SetFile(file string) {
	r.file = file
}

// Report writes findings to a CSV file
func (r *CSVReporter) Report(findings []detectors.Finding) error {
	f, err := os.Create(r.file)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	// Write header
	if err := w.Write([]string{"Rule", "Severity", "File", "Line", "Message"}); err != nil {
		return err
	}

	// Write findings
	for _, finding := range findings {
		if err := w.Write([]string{
			finding.Rule,
			string(finding.Severity),
			finding.File,
			fmt.Sprintf("%d", finding.Line),
			finding.Message,
		}); err != nil {
			return err
		}
	}

	return nil
}
