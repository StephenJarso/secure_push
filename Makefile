.PHONY: help build test lint clean install docker-build docker-run

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the secure-push binary
	go build -o secure-push ./cmd/secure-push

test: ## Run all tests
	go test -v -race ./...

test-short: ## Run short tests only
	go test -short ./...

test-coverage: ## Run tests with coverage report
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	echo "Coverage report generated: coverage.html"

lint: ## Run linter
	golangci-lint run

lint-fix: ## Run linter and fix issues
	golangci-lint run --fix

clean: ## Clean build artifacts
	rm -f secure-push
	rm -f coverage.out coverage.html
	go clean

install: build ## Build and install secure-push
	cp secure-push $(GOPATH)/bin/

docker-build: ## Build Docker image
	docker build -t secure-push:latest .

docker-run: ## Run secure-push in Docker
	docker run --rm -v $(PWD):/workspace secure-push:latest /workspace

bench: ## Run benchmarks
	go test -bench=. -benchmem ./...

fmt: ## Format code
	go fmt ./...

vet: ## Run go vet
	go vet ./...

all: fmt vet lint test build ## Run all checks and build
