# Reporters Guide

## Overview

Reporters format and output scan results. Secure Push supports multiple output formats for different use cases.

## Reporter Interface

```go
type Reporter interface {
    Report(findings []Finding) error
}
```

## Built-in Reporters

| Reporter | Description | Use Case |
|----------|-------------|----------|
| Console | Human-readable terminal output | Local development |
| JSON | Machine-readable JSON | CI/CD pipelines |
| GitHub | GitHub Actions annotation format | GitHub Actions |
| CSV | Comma-separated values | Data analysis, spreadsheets |
| SARIF | Static Analysis Results Interchange Format | CI/CD, GitHub Code Scanning, IDEs |

## Creating a Custom Reporter

1. Create a new file in `internal/reporters/`
2. Implement the `Reporter` interface
3. Add CLI flag to select the reporter
4. Add tests

## Example: CSV Reporter

```go
package reporters

import (
    "encoding/csv"
    "os"
    "secure-push/internal/detectors"
)

type CSVReporter struct {
    file string
}

func NewCSVReporter(file string) *CSVReporter {
    return &CSVReporter{file: file}
}

func (r *CSVReporter) Report(findings []detectors.Finding) error {
    f, err := os.Create(r.file)
    if err != nil {
        return err
    }
    defer f.Close()

    w := csv.NewWriter(f)
    defer w.Flush()

    // Write header
    if err := w.Write([]string{"Rule", "Severity", "File", "Line", "Message"}); err != nil {
        return err
    }

    // Write findings
    for _, f := range findings {
        if err := w.Write([]string{
            f.Rule,
            f.Severity,
            f.File,
            fmt.Sprintf("%d", f.Line),
            f.Message,
        }); err != nil {
            return err
        }
    }

    return nil
}
```

## Reporter Output Examples

### Console Output

```
✗ Found 2 potential security issues:

1. 🔴 [CRITICAL] .env:1
   Rule: ENV_FILE
   .env file should not be committed
```

### JSON Output

```json
{
  "total": 2,
  "findings": [
    {
      "severity": "CRITICAL",
      "rule": "ENV_FILE",
      "file": ".env",
      "line": 1,
      "message": ".env file should not be committed"
    }
  ]
}
```

### GitHub Output

```
::error file=.env,line=1,title=ENV_FILE [CRITICAL]::.env file should not be committed
```

### CSV Output

```csv
Rule,Severity,File,Line,Message
ENV_FILE,CRITICAL,.env,1,.env file should not be committed
```

### SARIF Output

```json
{
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Secure Push",
          "version": "0.1.0",
          "rules": [
            {
              "id": "ENV_FILE",
              "shortDescription": {
                "text": "ENV_FILE security issue detected"
              },
              "defaultConfiguration": {
                "level": "error"
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "ENV_FILE",
          "message": {
            "text": ".env file should not be committed"
          },
          "locations": [
            {
              "id": 1,
              "uri": ".env",
              "properties": {
                "line": 1
              }
            }
          ]
        }
      ]
    }
  ]
}
```

SARIF is the industry standard format for static analysis tools. It's supported by:
- GitHub Code Scanning
- Azure DevOps
- GitLab
- VS Code
- Many other CI/CD and IDE tools
