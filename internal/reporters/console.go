package reporters

import (
	"fmt"
	"os"
	"strings"

	"secure-push/internal/detectors"
)

type ConsoleReporter struct{}

func (r *ConsoleReporter) Report(findings []detectors.Finding) error {
	if len(findings) == 0 {
		fmt.Println("✓ No sensitive data found")
		return nil
	}

	fmt.Printf("✗ Found %d potential security issues:\n\n", len(findings))

	for i, f := range findings {
		severityIcon := getSeverityIcon(f.Severity)
		fmt.Printf("%d. %s [%s] %s:%d\n", i+1, severityIcon, strings.ToUpper(string(f.Severity)), f.File, f.Line)
		fmt.Printf("   Rule: %s\n", f.Rule)
		fmt.Printf("   %s\n", f.Message)
		if i < len(findings)-1 {
			fmt.Println()
		}
	}

	fmt.Println()
	fmt.Printf("Total: %d issues found (%d critical, %d high, %d medium, %d low)\n",
		len(findings),
		countBySeverity(findings, detectors.Critical),
		countBySeverity(findings, detectors.High),
		countBySeverity(findings, detectors.Medium),
		countBySeverity(findings, detectors.Low),
	)

	os.Exit(1)
	return nil
}

func getSeverityIcon(s detectors.Severity) string {
	switch s {
	case detectors.Critical:
		return "🔴"
	case detectors.High:
		return "🟠"
	case detectors.Medium:
		return "🟡"
	case detectors.Low:
		return "🔵"
	default:
		return "⚪"
	}
}

func countBySeverity(findings []detectors.Finding, severity detectors.Severity) int {
	count := 0
	for _, f := range findings {
		if f.Severity == severity {
			count++
		}
	}
	return count
}
