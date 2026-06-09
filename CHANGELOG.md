# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive test suite for env.go detector
- Secrets detector with common secret patterns
- Auth detector for AWS keys, tokens, and credentials
- Config detector for config file leaks
- Reporter interface with console, JSON, and GitHub Actions support
- Configuration file parsing with YAML support
- Ignore/whitelist patterns support
- Binary file detection and skipping
- File size limits
- Parallel scanning with worker pools
- File type detection
- Structured logging package
- Pre-commit hook script
- Multi-stage Dockerfile
- Benchmarks for scanner performance
- Integration tests
- GitHub Actions CI workflow
- golangci-lint configuration
- Makefile with testing and building targets

### Changed
- Improved env.go with additional .env patterns and edge cases
- Enhanced scanner with config integration
