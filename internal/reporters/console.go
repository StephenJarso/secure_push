package reporters

import (
	"fmt"
	"strings"

	"secure-push/internal/detectors"
)

type ConsoleReporter struct{}

// Format returns the console output as a string
func (r *ConsoleReporter) Format(findings []detectors.Finding) string {
	var sb strings.Builder

	if len(findings) == 0 {
		sb.WriteString("✓ No sensitive data found\n")
		return sb.String()
	}

	sb.WriteString(fmt.Sprintf("✗ Found %d potential security issues:\n\n", len(findings)))

	for i, f := range findings {
		severityIcon := getSeverityIcon(f.Severity)
		sb.WriteString(fmt.Sprintf("%d. %s [%s] %s:%d\n", i+1, severityIcon, strings.ToUpper(string(f.Severity)), f.File, f.Line))
		sb.WriteString(fmt.Sprintf("   Rule: %s\n", f.Rule))
		sb.WriteString(fmt.Sprintf("   %s\n", f.Message))
		if i < len(findings)-1 {
			sb.WriteString("\n")
		}
	}

	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("Total: %d issues found (%d critical, %d high, %d medium, %d low)\n",
		len(findings),
		countBySeverity(findings, detectors.Critical),
		countBySeverity(findings, detectors.High),
		countBySeverity(findings, detectors.Medium),
		countBySeverity(findings, detectors.Low),
	))

	return sb.String()
}

func (r *ConsoleReporter) Report(findings []detectors.Finding) error {
	fmt.Print(r.Format(findings))

	if len(findings) > 0 {
		return fmt.Errorf("scan found %d security issues", len(findings))
	}
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
