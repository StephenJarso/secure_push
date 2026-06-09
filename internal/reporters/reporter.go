package reporters

import "secure-push/internal/detectors"

type Reporter interface {
	Report(findings []detectors.Finding) error
}
