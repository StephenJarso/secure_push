# Design Document

## Overview

Secure Push is a security gate for codebases that runs before code is committed and in CI/CD pipelines. It is designed to be fast, developer-friendly, and specifically tuned for AI-generated code risks.

## Architecture

```
┌─────────────────┐
│   CLI (main)    │
│  cmd/secure-push│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│    Scanner      │
│ internal/scanner│
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────┐
│          Detectors                  │
│  internal/detectors/                │
│  ├── detector.go (interface)        │
│  ├── env.go                         │
│  ├── secrets.go                     │
│  ├── auth.go                        │
│  └── config.go                      │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────┐
│   Reporters     │
│internal/reporters│
└─────────────────┘
```

## Core Concepts

### Detector Interface

Every security rule implements the `Detector` interface:

```go
type Detector interface {
    Name() string
    Severity() Severity
    Detect(content string, filename string) ([]Finding, error)
}
```

This design allows:
- Easy addition of new rules without modifying the scanner
- Unit testing of detectors in isolation
- Parallel execution of detectors

### Severity Levels

| Severity | Description |
|----------|-------------|
| CRITICAL | Immediate security risk, must block commit |
| HIGH | Significant risk, should block commit |
| MEDIUM | Potential risk, warn but don't block |
| LOW | Informational, for awareness only |

### Scanner Design

The scanner uses `errgroup` for parallel file processing:
- Walks the file tree, skipping hidden directories (`.git`, `.idea`, etc.)
- Reads each file and passes content to all registered detectors
- Collects findings with mutex protection for concurrent access
- Returns all findings or the first error encountered

### Why `internal/`?

Go's `internal/` directory makes packages unimportable by external projects. This provides:
- API stability while the project is young
- Freedom to refactor internal structures
- Clear separation between public and private APIs

## Performance Considerations

- **Parallel scanning**: Files are processed concurrently using goroutines
- **Streaming**: Large files are read entirely into memory (acceptable for source code)
- **Skip patterns**: Hidden directories and common non-code paths are skipped
- **Target**: ~5,000 files per second on a typical laptop

## Extension Points

1. **New Detectors**: Add a new file in `internal/detectors/` implementing the `Detector` interface
2. **New Reporters**: Add a new file in `internal/reporters/` implementing the `Reporter` interface
3. **Configuration**: Extend `internal/config/config.go` to support new settings
4. **CLI Commands**: Add new subcommands in `cmd/secure-push/`

## Future Improvements

- AST-based analysis for deeper code inspection
- Incremental scanning for large monorepos
- Caching of scan results
- Custom rule language for user-defined detectors
