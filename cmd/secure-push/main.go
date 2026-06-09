package main

import (
	"flag"
	"fmt"
	"os"

	"secure-push/internal/config"
	"secure-push/internal/detectors"
	"secure-push/internal/logger"
	"secure-push/internal/reporters"
	"secure-push/internal/scanner"
)

func main() {
	configPath := flag.String("config", "", "Path to configuration file")
	outputFormat := flag.String("output", "console", "Output format: console, json, github")
	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: secure-push [options] <path>")
		fmt.Fprintln(os.Stderr, "Options:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	path := args[0]

	logLevel := logger.Info
	if *verbose {
		logLevel = logger.Debug
	}
	log := logger.New(logLevel)

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Error("Failed to load config: %v", err)
		os.Exit(1)
	}

	detectorList := []detectors.Detector{
		&detectors.EnvDetector{},
		&detectors.SecretsDetector{},
		&detectors.AuthDetector{},
		&detectors.ConfigDetector{},
	}

	s := scanner.New(detectorList, cfg, log)

	log.Info("Scanning %s for sensitive data...", path)
	findings, err := s.Scan(path)
	if err != nil {
		log.Error("Scan failed: %v", err)
		os.Exit(1)
	}

	var reporter reporters.Reporter
	switch *outputFormat {
	case "json":
		reporter = &reporters.JSONReporter{}
	case "github":
		reporter = &reporters.GitHubReporter{}
	default:
		reporter = &reporters.ConsoleReporter{}
	}

	if err := reporter.Report(findings); err != nil {
		log.Error("Failed to report findings: %v", err)
		os.Exit(1)
	}
}
