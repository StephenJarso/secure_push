package main

import (
	"flag"
	"fmt"
	"os"
	"github.com/stephenjarso/secure-push/internal/detectors"
	"github.com/stephenjarso/secure-push/internal/scanner"
)

func main() {
	path := flag.String("path", ".", "Path to scan")
	flag.Parse()

	s := scanner.New(
		&detectors.EnvDetector{},
		// Add more detectors here later
	)

	findings, err := s.Scan(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Scan failed: %v\n", err)
		os.Exit(1)
	}

	if len(findings) > 0 {
		for _, f := range findings {
			fmt.Printf("%s %s detected in %s:%d\n", f.Severity, f.Rule, f.File, f.Line)
		}
		os.Exit(1) // Fail the scan
	}

	fmt.Println("✓ No issues found")
}
