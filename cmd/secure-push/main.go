package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"secure-push/internal/config"
	"secure-push/internal/detectors"
	"secure-push/internal/logger"
	"secure-push/internal/reporters"
	"secure-push/internal/scanner"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	subcommand := os.Args[1]

	switch subcommand {
	case "scan":
		runScan(os.Args[2:])
	case "pre-commit":
		runPreCommit()
	case "install":
		runInstall()
	case "version":
		fmt.Println("secure-push version 0.1.0")
	case "help", "-h", "--help":
		printUsage()
	default:
		// Treat as scan with path argument
		runScan(os.Args[1:])
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Secure Push - Security scanner for your codebase")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  secure-push scan [options] <path>     Scan a directory for security issues")
	fmt.Fprintln(os.Stderr, "  secure-push pre-commit              Run in pre-commit mode")
	fmt.Fprintln(os.Stderr, "  secure-push install                 Install pre-commit hook")
	fmt.Fprintln(os.Stderr, "  secure-push version                 Show version")
	fmt.Fprintln(os.Stderr, "  secure-push help                    Show help")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Options:")
	fmt.Fprintln(os.Stderr, "  -config string")
	fmt.Fprintln(os.Stderr, "        Path to configuration file")
	fmt.Fprintln(os.Stderr, "  -output string")
	fmt.Fprintln(os.Stderr, "        Output format: console, json, github, sarif, csv (default \"console\")")
	fmt.Fprintln(os.Stderr, "  -verbose")
	fmt.Fprintln(os.Stderr, "        Enable verbose logging")
}

func runScan(args []string) {
	scanFlags := flag.NewFlagSet("scan", flag.ExitOnError)
	configPath := scanFlags.String("config", "", "Path to configuration file")
	outputFormat := scanFlags.String("output", "console", "Output format: console, json, github")
	verbose := scanFlags.Bool("verbose", false, "Enable verbose logging")
	scanFlags.Parse(args)

	remainingArgs := scanFlags.Args()
	if len(remainingArgs) == 0 {
		fmt.Fprintln(os.Stderr, "Error: path argument required")
		printUsage()
		os.Exit(1)
	}

	path := remainingArgs[0]

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
	case "sarif":
		reporter = &reporters.SARIFReporter{}
	case "csv":
		reporter = reporters.NewCSVReporter("findings.csv")
	default:
		reporter = &reporters.ConsoleReporter{}
	}

	if err := reporter.Report(findings); err != nil {
		log.Error("Failed to report findings: %v", err)
		os.Exit(cfg.ExitCode)
	}

	if len(findings) > 0 {
		os.Exit(cfg.ExitCode)
	}
}

func runPreCommit() {
	log := logger.New(logger.Info)

	// Get staged files from git
	files, err := getStagedFiles()
	if err != nil {
		log.Error("Failed to get staged files: %v", err)
		os.Exit(1)
	}

	if len(files) == 0 {
		log.Info("No staged files to scan")
		return
	}

	cfg, err := config.Load("")
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

	var allFindings []detectors.Finding
	for _, file := range files {
		findings, err := s.ScanFile(file)
		if err != nil {
			log.Error("Error scanning file %s: %v", file, err)
			continue
		}
		allFindings = append(allFindings, findings...)
	}

	if len(allFindings) > 0 {
		fmt.Fprintln(os.Stderr, "🚫 Commit blocked by Secure Push")
		fmt.Fprintln(os.Stderr, "")
		for _, f := range allFindings {
			fmt.Fprintf(os.Stderr, "%s [%s] %s:%d\n", f.Rule, f.Severity, f.File, f.Line)
			fmt.Fprintf(os.Stderr, "   %s\n", f.Message)
		}
		os.Exit(1)
	}

	fmt.Println("✓ No security issues found in staged files")
}

func runInstall() {
	hookPath := ".git/hooks/pre-commit"

	// Check if .git directory exists
	if _, err := os.Stat(".git"); os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "Error: not a git repository")
		os.Exit(1)
	}

	// Create hooks directory if it doesn't exist
	if err := os.MkdirAll(".git/hooks", 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating hooks directory: %v\n", err)
		os.Exit(1)
	}

	// Check if hook already exists
	if _, err := os.Stat(hookPath); err == nil {
		fmt.Fprintln(os.Stderr, "Warning: pre-commit hook already exists, skipping")
		return
	}

	// Create the hook script
	hookContent := `#!/bin/sh
# Secure Push pre-commit hook
secure-push pre-commit
`
	if err := os.WriteFile(hookPath, []byte(hookContent), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating pre-commit hook: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✓ Pre-commit hook installed successfully")
}

func getStagedFiles() ([]string, error) {
	cmd := exec.Command("git", "diff", "--cached", "--name-only")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	files := strings.Fields(string(out))
	return files, nil
}
