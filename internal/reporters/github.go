package reporters

import (
	"fmt"
	"strings"

	"secure-push/internal/detectors"
)

// GitHubReporter outputs findings in GitHub Actions annotation format
type GitHubReporter struct{}

// ToAnnotations returns GitHub Actions annotations as strings
func (r *GitHubReporter) ToAnnotations(findings []detectors.Finding) []string {
	var annotations []string

	for _, f := range findings {
		annotationType := r.getAnnotationType(f.Severity)
		title := fmt.Sprintf("[%s] %s", strings.ToUpper(string(f.Severity)), f.Rule)
		message := fmt.Sprintf("%s (line %d): %s", f.File, f.Line, f.Message)

		annotations = append(annotations, fmt.Sprintf("::%s file=%s,line=%d,title=%s::%s",
			annotationType, f.File, f.Line, title, message))
	}

	return annotations
}

// Report outputs findings as GitHub Actions workflow commands
func (r *GitHubReporter) Report(findings []detectors.Finding) error {
	if len(findings) == 0 {
		fmt.Println("::notice::No sensitive data found")
		return nil
	}

	for _, f := range findings {
		annotationType := r.getAnnotationType(f.Severity)
		title := fmt.Sprintf("[%s] %s", strings.ToUpper(string(f.Severity)), f.Rule)
		message := fmt.Sprintf("%s (line %d): %s", f.File, f.Line, f.Message)

		fmt.Printf("::%s file=%s,line=%d,title=%s::%s\n",
			annotationType, f.File, f.Line, title, message)
	}

	fmt.Printf("::notice::Scan complete: %d issues found\n", len(findings))

	if len(findings) > 0 {
		return fmt.Errorf("scan found %d security issues", len(findings))
	}

	return nil
}

func (r *GitHubReporter) getAnnotationType(severity detectors.Severity) string {
	switch severity {
	case detectors.Critical, detectors.High:
		return "error"
	case detectors.Medium:
		return "warning"
	case detectors.Low:
		return "notice"
	default:
		return "notice"
	}
}
