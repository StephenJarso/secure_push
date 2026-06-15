# Configuration Guide

## Overview

Secure Push can be configured using a `.secure-push.yaml` file in your repository root.

## Example Configuration

```yaml
# .secure-push.yaml
severity_threshold: HIGH

ignore_rules:
  - GENERIC_API_KEY

ignore_paths:
  - vendor/
  - testdata/
  - "**/*_test.go"

allowlist:
  - scripts/dev-only.sh
  - examples/fixtures/

custom_rules:
  - path: rules/custom-secrets.yaml
    severity: CRITICAL

max_file_size: 10485760

enable_detectors:
  - ENV_FILE
  - SECRETS
```

## Configuration Options

### severity_threshold

Minimum severity that causes a scan to fail.

- `CRITICAL` - Only critical issues fail
- `HIGH` - High and critical issues fail (default)
- `MEDIUM` - Medium, high, and critical issues fail
- `LOW` - All issues fail

### ignore_rules

List of detector rule IDs to skip during scanning.

```yaml
ignore_rules:
  - GENERIC_API_KEY
  - OPEN_CORS
```

### ignore_paths

List of file paths or glob patterns to skip.

```yaml
ignore_paths:
  - vendor/
  - "**/*.min.js"
  - "**/node_modules/**"
```

### allowlist

List of specific files to allow even if they trigger detectors.

```yaml
allowlist:
  - scripts/dev-only.sh
  - testdata/fixtures/example.env
```

### custom_rules

List of custom rule files to load.

```yaml
custom_rules:
  - path: rules/my-company-secrets.yaml
    severity: CRITICAL
```

### max_file_size

Maximum file size in bytes to scan. Files larger than this are skipped.

```yaml
max_file_size: 10485760  # 10MB
```

### enable_detectors

List of specific detectors to enable. If set, only these detectors will run.

```yaml
enable_detectors:
  - ENV_FILE
  - SECRETS
```

### disable_detectors

List of specific detectors to disable.

```yaml
disable_detectors:
  - CONFIG_FILE
```

### output_format

Output format for scan results.

- `console` - Human-readable console output (default)
- `json` - JSON format for programmatic processing
- `csv` - CSV format for spreadsheet import
- `sarif` - SARIF format for CI/CD integration

```yaml
output_format: sarif
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECURE_PUSH_CONFIG` | Path to config file | `.secure-push.yaml` |
| `SECURE_PUSH_THRESHOLD` | Override severity threshold | - |
| `SECURE_PUSH_VERBOSE` | Enable verbose output | `false` |

## Precedence

1. Command-line flags
2. Environment variables
3. `.secure-push.yaml` config file
4. Default values

## Common Configuration Patterns

### Minimal Configuration

```yaml
severity_threshold: HIGH
ignore_paths:
  - vendor/
  - node_modules/
```

### Development Environment

```yaml
severity_threshold: MEDIUM
ignore_rules:
  - GENERIC_API_KEY
allowlist:
  - testdata/
```

### CI/CD Configuration

```yaml
severity_threshold: CRITICAL
ignore_paths:
  - "**/*.min.js"
  - "**/*.map"
