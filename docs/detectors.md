# Detectors Guide

## Overview

Detectors are the core of Secure Push. Each detector identifies a specific class of security issue.

## Detector Interface

```go
type Detector interface {
    Name() string
    Severity() Severity
    Detect(content string, filename string) ([]Finding, error)
}
```

## Built-in Detectors

| Detector | Severity | Description |
|----------|----------|-------------|
| ENV_FILE | CRITICAL | Detects committed `.env` files |
| AWS_SECRET_KEY | CRITICAL | Detects AWS secret keys |
| GENERIC_API_KEY | HIGH | Detects generic API keys |
| HARDCODED_PASSWORD | CRITICAL | Detects hardcoded passwords |

## Creating a Custom Detector

1. Create a new file in `internal/detectors/`
2. Implement the `Detector` interface
3. Add comprehensive tests
4. Register in `scanner.go`

## Example: Generic API Key Detector

```go
package detectors

import (
    "regexp"
    "strings"
)

type GenericAPIKeyDetector struct{}

func (d *GenericAPIKeyDetector) Name() string {
    return "GENERIC_API_KEY"
}

func (d *GenericAPIKeyDetector) Severity() Severity {
    return High
}

func (d *GenericAPIKeyDetector) Detect(content string, filename string) ([]Finding, error) {
    var findings []Finding
    
    // Pattern for common API key formats
    patterns := []string{
        `api[_-]?key\s*[:=]\s*['"][a-zA-Z0-9]{20,}['"]`,
        `apikey\s*[:=]\s*['"][a-zA-Z0-9]{20,}['"]`,
    }
    
    lines := strings.Split(content, "\n")
    for i, line := range lines {
        for _, pattern := range patterns {
            re := regexp.MustCompile(pattern)
            if re.MatchString(line) {
                findings = append(findings, Finding{
                    Rule:     d.Name(),
                    Severity: d.Severity(),
                    File:     filename,
                    Line:     i + 1,
                    Message:  "Potential API key detected",
                })
            }
        }
    }
    
    return findings, nil
}
```

## Testing Detectors

Use table-driven tests:

```go
func TestGenericAPIKeyDetector(t *testing.T) {
    tests := []struct {
        name     string
        content  string
        filename string
        want     int
    }{
        {"api key found", "api_key = 'abc123def456'", "config.go", 1},
        {"no api key", "package main", "main.go", 0},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            d := &GenericAPIKeyDetector{}
            got, err := d.Detect(tt.content, tt.filename)
            if err != nil {
                t.Fatalf("error: %v", err)
            }
            if len(got) != tt.want {
                t.Fatalf("got %d findings, want %d", len(got), tt.want)
            }
        })
    }
}
```
