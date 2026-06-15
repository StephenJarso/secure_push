# Development Guide

## Prerequisites

- Go 1.22 or later
- git
- make (recommended)

## Setup

```bash
git clone https://github.com/StephenJarso/secure_push.git
cd secure_push
go mod download
```

## Building

```bash
make build
# Binary will be in bin/secure-push
```

Or directly:
```bash
go build -o bin/secure-push ./cmd/secure-push
```

## Running Tests

```bash
make test
# Or:
go test -v -race ./...
```

## Linting

```bash
make lint
# Requires golangci-lint to be installed
```

## Code Style

- Use `gofmt` and `goimports`
- Functions should not exceed 50 lines
- All exported functions and types must have comments
- Handle errors explicitly, never use `panic` in production code

## Adding a New Detector

1. Create a new file in `internal/detectors/`
2. Implement the `Detector` interface
3. Add tests in `internal/detectors/`
4. Register the detector in `internal/scanner/scanner.go`
5. Update README.md with the new detector

Detector tests should include positive matches, negative matches, line number assertions, and false-positive guards for broad patterns.

## Adding a New Reporter

1. Create a new file in `internal/reporters/`
2. Implement the `Reporter` interface
3. Add CLI flag to select the reporter
4. Update documentation

## Pre-commit Hook

```bash
make pre-commit
```

This installs the pre-commit hook that runs Secure Push on staged files.
