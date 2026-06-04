# Contributing to Secure Push

Thanks for your interest in contributing to **Secure Push**! Contributions help improve detection accuracy, reduce false positives, and make the tool safer and more useful for developers relying on AI-assisted coding. Whether you’re fixing a bug, adding a detector, or improving docs, your help is appreciated.

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). Please make sure you read and follow it in all interactions.

---

## 1. Getting Started

### Forking and Cloning

1. Fork the repository on GitHub.
2. Clone your fork locally:

```bash
git clone https://github.com/<your-username>/secure-push.git
cd secure-push
```
### Prerequisites

Make sure you have the following installed:

 - Go (version 1.21 or later)
 - git
 - make (recommended for common tasks)
Installing Dependencies

Secure Push uses Go modules. Dependencies will be downloaded automatically:
```
go mod download
```
Building From Source
```
make build
```
Or directly with Go:
```
go build ./cmd/secure-push
```
Running Tests
```
make test
```
Or:
```
go test ./...
```
## 2. Project Structure
```
secure-push/
├── cmd/           # Application entry points (CLI commands, flags, wiring)
├── internal/      # Core logic not meant to be used as a public API
├── pkg/           # Reusable packages that could be imported by other projects
├── detectors/     # Security detectors and related logic
└── scripts/       # Utility scripts for development and CI
```
Directory Overview
 - cmd/
    - Contains the CLI entry point and command definitions. This is where flags, subcommands, and execution flow are wired together.
 - internal/
    - Holds core scanning logic, rule engines, and utilities that should not be imported by external projects.
 - pkg/
    - Contains reusable components that may be safely consumed outside of Secure Push (e.g., data structures or helper libraries).
 - detectors/
    - All security detectors live here. Each detector is responsible for identifying a specific class of security issue.
- scripts/
    - Helper scripts for development, testing, and CI workflows.

## 3. Development Workflow
- Find an existing issue or create a new one describing the change.
Create a new branch:
```
feature/<short-description>
fix/<short-description>
```
- Make your changes along with appropriate tests.
- Run formatting, linting, and tests locally.
- Submit a pull request with a clear description of what changed and why.

## 4. Adding a New Detector

Follow these steps to add a new detector.

#### Step 1: Create a Detector File

Create a new file in internal/detectors/:
```
// internal/detectors/example_detector.go
package detectors

type ExampleDetector struct{}
```
#### Step 2: Implement the Detector Interface
```
func (d *ExampleDetector) Name() string {
	return "EXAMPLE_DETECTOR"
}

func (d *ExampleDetector) Severity() Severity {
	return High
}

func (d *ExampleDetector) Detect(input ScanInput) ([]Finding, error) {
	// TODO: implement detection logic
	return nil, nil
}
```
#### Step 3: Add Tests

Create tests in internal/detectors/test/:
```
// internal/detectors/test/example_detector_test.go
package test

func TestExampleDetector(t *testing.T) {
	// TODO: write test cases
}
```
#### Step 4: Register the Detector

Register the detector in scanner.go so it is executed during scans.
```
// scanner.go
registerDetector(&ExampleDetector{})
```
#### Step 5: Document the Detector

Add the detector to the Supported Detectors table in README.md.

## 5. Code Style Guide

Please follow these rules:

- Formatting
    - Use gofmt and goimports on all Go files.
- Naming
    - Use clear, descriptive names.
    - Avoid abbreviations unless they are well-known.
- Error Handling
    - Always handle errors explicitly.
    - Do not use panic in production code.
- Comments
    - All exported functions and types must have comments.
- Function Size
    - Functions should generally not exceed 50 lines.
- Package Organization
    - Keep packages small and focused on a single responsibility.
## 6. Testing Requirements
- Unit tests are required for all new functionality.
- Minimum test coverage target: 80%.
- Integration tests should be added for end-to-end workflows.
- Performance-sensitive code should include benchmark tests.
Example Test Structure
```
func TestSecretDetector(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected int
	}{
		// TODO: add test cases
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// TODO: implement test logic
		})
	}
}
```
## 7. Pull Request Process

Before submitting a PR, ensure that:

- All tests pass locally
- No linting warnings are present
- Documentation is updated if behavior changes
- The change is added to CHANGELOG.md under Unreleased
Pull Request Template
## What does this PR do?
Describe your change.

## Which detectors does it affect?
- [ ] Secrets
- [ ] Environment
- [ ] Auth
- [ ] New detector: _______

## Testing done
- [ ] Unit tests added
- [ ] Manually tested with a real codebase

## Checklist
- [ ] Code follows style guide
- [ ] Self-review completed

## 8. Release Process (Maintainers Only)
 - Versioning follows Semantic Versioning.
 - Create a release branch from main.
 - Update CHANGELOG.md.
 - Build binaries for all supported platforms.
 - Publish the release on GitHub with release notes.

## 9. Getting Help
Bug reports: GitHub Issues
Feature ideas & discussions: GitHub Discussions
Security issues: email security@secure-push.dev

We’re glad you’re here — happy contributing! 🚀