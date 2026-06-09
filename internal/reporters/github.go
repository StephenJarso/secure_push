package reporters

import (
	"fmt"
	"os"
	"strings"

	"secure-push/internal/detectors"
)

type GitHubReporter struct{}

func (r *GitHubReporter) Report(findings []detectors.Finding) error {
	if len(findings) == 0 {
		fmt.Println("::notice::No sensitive data found")
		return nil
	}

	for _, f := range findings {
		severity := strings.ToUpper(string(f.Severity))
		switch f.Severity {
		case detectors.Critical:
			fmt.Printf("::error file=%s,line=%d,title=%s [%s]::%s\n",
				f.File, f.Line, f.Rule, severity, f.Message)
		case detectors.High:
			fmt.Printf("::error file=%s,line=%d,title=%s [%s]::%s\n",
				f.File, f.Line, f.Rule, severity, f.Message)
		case detectors.Medium:
			fmt.Printf("::warning file=%s,line=%d,title=%s [%s]::%s\n",
				f.File, f.Line, f.Rule, severity, f.Message)
		case detectors.Low:
			fmt.Printf("::notice file=%s,line=%d,title=%s [%s]::%s\n",
				f.File, f.Line, f.Rule, severity, f.Message)
		}
	}

	if len(findings) > 0 {
		os.Exit(1)
	}

	return nil
}
