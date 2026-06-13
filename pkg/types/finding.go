package types

// Finding represents a security finding
type Finding struct {
	Severity string
	Rule     string
	File     string
	Line     int
	Message  string
}
