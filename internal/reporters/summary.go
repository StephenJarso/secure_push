package reporters

import (
	"fmt"
	"sort"

	"secure-push/internal/detectors"
)

// SummaryReporter outputs scan summary statistics
type SummaryReporter struct{}

// Report outputs summary statistics for the scan
func (r *SummaryReporter) Report(findings []detectors.Finding) error {
	fmt.Println("=== Secure Push Scan Summary ===")
	fmt.Println()

	if len(findings) == 0 {
		fmt.Println("✓ No sensitive data found")
		return nil
	}

	// Total findings
	fmt.Printf("Total findings: %d\n\n", len(findings))

	// By severity
	fmt.Println("By severity:")
	criticalCount := countBySeverity(findings, detectors.Critical)
	highCount := countBySeverity(findings, detectors.High)
	mediumCount := countBySeverity(findings, detectors.Medium)
	lowCount := countBySeverity(findings, detectors.Low)
	fmt.Printf("  Critical: %d\n", criticalCount)
	fmt.Printf("  High:     %d\n", highCount)
	fmt.Printf("  Medium:   %d\n", mediumCount)
	fmt.Printf("  Low:      %d\n", lowCount)
	fmt.Println()

	// By rule
	fmt.Println("By rule:")
	ruleCounts := make(map[string]int)
	for _, f := range findings {
		ruleCounts[f.Rule]++
	}

	rules := make([]string, 0, len(ruleCounts))
	for rule := range ruleCounts {
		rules = append(rules, rule)
	}
	sort.Strings(rules)

	for _, rule := range rules {
		fmt.Printf("  %s: %d\n", rule, ruleCounts[rule])
	}
	fmt.Println()

	// By file
	fmt.Println("By file:")
	fileCounts := make(map[string]int)
	for _, f := range findings {
		fileCounts[f.File]++
	}

	type fileStat struct {
		file  string
		count int
	}
	fileStats := make([]fileStat, 0, len(fileCounts))
	for file, count := range fileCounts {
		fileStats = append(fileStats, fileStat{file, count})
	}
	sort.Slice(fileStats, func(i, j int) bool {
		return fileStats[i].count > fileStats[j].count
	})

	for _, fs := range fileStats {
		fmt.Printf("  %s: %d\n", fs.file, fs.count)
	}

	if len(findings) > 0 {
		return fmt.Errorf("scan found %d security issues", len(findings))
	}

	return nil
}
