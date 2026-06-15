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
- Slack token detector (xoxb, xoxa, xoxp, xoxr, xoxs)
- Discord webhook URL detector
- Telegram bot token detector
- Azure Key Vault detector
- Personal access token detector
- Provider access token detectors for Figma, Notion, Linear, Auth0, and Intercom
- Scanner binary detection benchmarks
- Hardcoded password pattern detection
- Connection string pattern detection
- API key header pattern detection
- Authorization header pattern detection
- Webhook URL pattern detection
- .envrc file detection
- .env.sample file detection
- SARIF output format reporter for CI/CD integration
- Homebrew tap formula for installation
- VS Code extension manifest

### Changed
- Improved env.go with additional .env patterns and edge cases
- Enhanced scanner with config integration
- Updated main.go to support sarif output format
- Added GitHub Actions release workflow

### Fixed
- Fixed .env.* file detection in config detector
- Fixed duplicate test cases in env_test.go
- Fixed integration test for multiple detectors

### Security
- Added comprehensive test coverage for all detectors
