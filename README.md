# Secure Push 
**Prevent secrets, insecure configs, and unsafe AI-generated code from ever reaching your Git repository.**
**Secure Push is designed for developers and teams using AI-assisted coding tools who want security guarantees without slowing down development.**

> Badges (coming soon)  
> ![Go Version]  
> ![Test Coverage]  
> ![License]  
> ![GitHub Actions Status]

---

## 1. The Problem

Modern developers increasingly rely on AI coding tools to move fast, but speed often comes at the cost of security. AI-generated code frequently includes hardcoded secrets, insecure defaults, or missing authentication checks that slip past reviews. This problem affects individual developers, startups, and large teams shipping code quickly under pressure.

---

## 2. Solution

**Secure Push** is a security gate for your codebase that runs **before code is committed and again in CI**.

### What Secure Push Detects
Secure Push scans for:
- Hardcoded secrets (API keys, tokens, passwords)
- `.env` and environment configuration leaks
- Missing or misconfigured authentication middleware
- Insecure framework defaults
- Unsafe CI/CD configuration
- High-risk AI-generated patterns

### How It Works
- **Pre-commit hook** blocks insecure code before it enters Git history
- **CI mode** enforces security rules in GitHub Actions, GitLab CI, and more

### What Makes It Different
Unlike generic secret scanners, Secure Push is **developer-first**:
- Built specifically for AI-generated code risks
- Fast enough to run on every commit
- Opinionated security rules with low false positives
- Simple YAML configuration, no complex policy language

---

## 3. Quick Start

### Install Secure Push

#### Option 1: Download Binary
```bash
curl -sSL https://example.com/secure-push/install.sh | bash
```
#### Option 2: Go Install

```go install github.com/secure-push/secure-push@latest```
#### Option 3: Homebrew
```brew install secure-push```
#### Run Your First Scan
```secure-push scan .```
#### Install Pre-Commit Hook
```secure-push install```

## 4. Features (Detailed)
- Secret detection – Finds AWS keys, JWTs, OAuth tokens, private keys, and generic high-entropy secrets.
- Environment file scanning – Blocks committed .env files and exposed environment variables.
- Auth middleware checking – Detects missing authentication or authorization in common web frameworks.
- Configuration validation – Flags insecure defaults in Docker, CI, and app configs.
- CI/CD integration – Produces machine-readable output for automated pipelines.

## 5. Usage Examples
#### Example 1: Basic Scan
```$ secure-push scan ./myproject```

## Output
```
CRITICAL  AWS_SECRET_KEY detected in config/aws.go:12
HIGH      Missing authentication middleware in api/routes.go:4

✖ Scan failed: 2 security issues found
```
#### Example 2: Pre-Commit Mode
```$ secure-push pre-commit```

  ### Blocked Commit Message

```🚫 Commit blocked by Secure Push

CRITICAL: .env file detected
File: .env

Fix the issue or add an explicit ignore rule to proceed.
```
#### Example 3: JSON Output for CI
```$ secure-push scan --format json```
``` JSON
{
  "summary": {
    "critical": 1,
    "high": 2,
    "medium": 0
  },
  "findings": [
    {
      "rule": "AWS_SECRET_KEY",
      "severity": "CRITICAL",
      "file": "config/aws.go",
      "line": 12
    }
  ]
}
```
## 6. Configuration

Create a configuration file in your repo root:
```
# .secure-push.yaml
severity_threshold: HIGH

ignore_rules:
  - GENERIC_API_KEY

ignore_paths:
  - vendor/
  - testdata/

allowlist:
  - scripts/dev-only.sh
  ```
 ## What You Can Configure
   - Ignore specific detectors
   - Whitelist files or directories
   - Set minimum severity that fails a scan
   - Customize output formats

## 7. Supported Detectors

| Detector                  | Severity  | False Positive Risk |
|---------------------------|-----------|---------------------|
| AWS Keys                  | CRITICAL  | Low                 |
| GitHub Tokens             | CRITICAL  | Low                 |
| `.env` Files              | CRITICAL  | None                |
| Generic API Keys          | HIGH      | Medium              |
| Private SSH Keys          | CRITICAL  | Low                 |
| Missing Auth Middleware   | HIGH      | Medium              |
| Open CORS Configuration   | MEDIUM    | Medium              |
| Insecure JWT Settings     | HIGH      | Low                 |
| Hardcoded Passwords       | CRITICAL  | Medium              |
| Public S3 Buckets         | HIGH      | Low                 |

## 8. Integration Guide
 ### Pre-Commit Hook (Manual)
 ```
ln -s ../../secure-push/hooks/pre-commit .git/hooks/pre-commit
```
### GitHub Actions
```
name: Secure Push Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Secure Push
        run: secure-push scan --format json
```       
### GitLab CI
```
secure_push:
  script:
    - secure-push scan
 ```   
### Makefile Target
```
security:
	secure-push scan .
```
## 9. Performance
- Speed: ~5,000 files per second on a typical laptop
- Memory Usage: <100MB for large repositories
- Monorepos: Fully supported with incremental scanning
## 10. Roadmap
v2
 - AST-based code analysis
 - Smarter AI-specific detectors
 - Performance improvements
 
v3
 - Auto-fix mode for common issues
 - VS Code extension
 - Custom rule language

## 11. Contributing

We love contributors!  
See [CONTRIBUTING.md](CONTRIBUTING.md) for details on:

- Development setup
- Adding new detectors
- Testing requirements
- Code style guide
## 12. License

Secure Push is released under the MIT License.