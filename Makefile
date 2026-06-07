.PHONY: build test lint clean install pre-commit help

# Variables
BINARY_NAME=secure-push
BUILD_DIR=bin
GO=go
GOLANGCI=golangci-lint

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the binary
	$(GO) build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/secure-push

test: ## Run tests
	$(GO) test -v -race -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

lint: ## Run linter
	$(GOLANGCI) run ./...

clean: ## Remove build artifacts
	rm -rf $(BUILD_DIR)/
	rm -f coverage.out coverage.html

install: build ## Install binary to /usr/local/bin
	install -m 0755 $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)

pre-commit: ## Install pre-commit hook
	@echo "Installing pre-commit hook..."
	@mkdir -p .git/hooks
	@cp scripts/pre-commit .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "Pre-commit hook installed!"

deps: ## Download dependencies
	$(GO) mod download
	$(GO) mod tidy

fmt: ## Format code
	$(GO) fmt ./...

vet: ## Run go vet
	$(GO) vet ./...

check: fmt vet lint test ## Run all checks

.DEFAULT_GOAL := help
