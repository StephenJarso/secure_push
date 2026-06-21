package detectors

// Severity represents the severity level of a finding
type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
)

// Finding represents a security finding detected in code
type Finding struct {
	Severity Severity
	Rule     string
	File     string
	Line     int
	Message  string
}

// Detector is an interface for implementing new detection rules
// without having to change anything in the scanner
type Detector interface {
	Severity() Severity
	Name() string
	Detect(content string, filename string) ([]Finding, error)
}

// String returns the string representation of the severity
func (s Severity) String() string {
	return string(s)
}

// IsHigherThan checks if this severity is higher than another
func (s Severity) IsHigherThan(other Severity) bool {
	severityOrder := map[Severity]int{
		Low:      1,
		Medium:   2,
		High:     3,
		Critical: 4,
	}
	return severityOrder[s] > severityOrder[other]
}
