# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Makefile for local testing with Nektos/Act
# https://nektosact.com/

.PHONY: help install-act test test-verbose test-dry-run setup-secrets list-jobs clean check-prereqs info

# Detect OS and set Docker socket
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    # macOS - use Docker Desktop socket
    export DOCKER_HOST := unix://$(HOME)/.docker/run/docker.sock
endif

# Default target
help:
	@echo "Tag Validate Action - Local Testing with Nektos/Act"
	@echo ""
	@echo "Available targets:"
	@echo "  install-act      - Install Nektos/Act (macOS)"
	@echo "  test             - Run ALL tests locally (~15-20 min)"
	@echo "  setup-secrets    - Setup secrets file for local testing"
	@echo "  list-jobs        - List all available jobs"
	@echo "  clean            - Clean up Act containers and cache"
	@echo "  check-prereqs    - Check prerequisites"
	@echo "  info             - Show configuration info"
	@echo ""
	@echo "Prerequisites:"
	@echo "  - Docker must be running"
	@echo "  - Run 'make setup-secrets' first to configure secrets"
	@echo ""
	@echo "Quick Start:"
	@echo "  make install-act"
	@echo "  make setup-secrets"
	@echo "  make test"
	@echo ""

# Install Act (macOS with Homebrew)
install-act:
	@echo "Installing Nektos/Act..."
	@if command -v brew >/dev/null 2>&1; then \
		brew install act; \
	else \
		echo "Error: Homebrew not found. Install from https://brew.sh/"; \
		echo "Or install Act manually from https://nektosact.com/installation/"; \
		exit 1; \
	fi
	@echo "✓ Act installed successfully"
	@act --version

# Setup secrets file
setup-secrets:
	@if [ ! -f .secrets ]; then \
		echo "Creating .secrets file from template..."; \
		cp .secrets.example .secrets; \
		echo ""; \
		echo "✓ Created .secrets file"; \
		echo ""; \
		echo "IMPORTANT: Edit .secrets and add your GitHub token:"; \
		echo "  1. Create token at: https://github.com/settings/tokens"; \
		echo "  2. Add 'public_repo' scope"; \
		echo "  3. Copy token to GITHUB_TOKEN in .secrets"; \
		echo ""; \
		echo "Optional: Add GPG_PRIVATE_KEY for signature tests"; \
	else \
		echo "✓ .secrets file already exists"; \
	fi

# List all jobs in the workflow
list-jobs:
	@echo "Available test jobs:"
	@act -l -W .github/workflows/testing-act.yaml

# Run ALL tests (single comprehensive job)
test: setup-secrets
	@echo "========================================"
	@echo "Running ALL tests locally"
	@echo "========================================"
	@echo ""
	@echo "Test Categories:"
	@echo "  • String Validation"
	@echo "  • Development Tags"
	@echo "  • Edge Cases"
	@echo "  • Local Tags"
	@echo "  • SSH Signatures"
	@echo "  • Remote Tags"
	@echo "  • Signature Detection"
	@echo "  • Python CLI Tests"
	@echo ""
	@echo "Estimated time: 15-20 minutes"
	@echo "Docker socket: $(DOCKER_HOST)"
	@echo ""
	@act workflow_dispatch -W .github/workflows/testing-act.yaml

# Verbose output for debugging
test-verbose: setup-secrets
	@echo "Running all tests with verbose output..."
	@act workflow_dispatch -W .github/workflows/testing-act.yaml -v

# Dry run to see what would be executed
test-dry-run:
	@echo "Dry run - showing what would be executed..."
	@act pull_request -W .github/workflows/testing-act.yaml -n

# Clean up Act containers and cache
clean:
	@echo "Cleaning up Act containers..."
	@docker ps -a | grep act- | awk '{print $$1}' | xargs -r docker rm -f || true
	@echo "Cleaning up Act volumes..."
	@docker volume ls | grep act- | awk '{print $$2}' | xargs -r docker volume rm || true
	@echo "✓ Cleanup complete"

# Check prerequisites
check-prereqs:
	@echo "Checking prerequisites..."
	@command -v docker >/dev/null 2>&1 || (echo "❌ Docker not found - install from https://docker.com" && exit 1)
	@docker info >/dev/null 2>&1 || (echo "❌ Docker not running - start Docker Desktop" && exit 1)
	@command -v act >/dev/null 2>&1 || (echo "❌ Act not installed - run 'make install-act'" && exit 1)
	@[ -f .secrets ] || (echo "⚠️  .secrets not found - run 'make setup-secrets'" && exit 1)
	@echo "✓ All prerequisites met"

# Show Act version and configuration
info:
	@echo "=== System Info ==="
	@echo "OS: $(UNAME_S)"
	@echo "Docker Host: $(DOCKER_HOST)"
	@echo ""
	@echo "=== Act Configuration ==="
	@act --version
	@echo ""
	@echo "=== Docker Info ==="
	@docker --version
	@docker info | grep "Server Version" || true
	@echo ""
	@echo "=== Secrets File ==="
	@[ -f .secrets ] && echo "✓ .secrets exists" || echo "❌ .secrets missing"
	@echo ""
	@echo "=== Available Test Jobs ==="
	@act -l -W .github/workflows/testing-act.yaml 2>/dev/null || echo "Unable to list jobs"
	@echo ""
	@echo "=== Quick Reference ==="
	@echo "  make test             # Run ALL tests (~15-20 min)"
	@echo "  make test-verbose     # All tests with verbose output"
	@echo "  make test-dry-run     # Dry run (see what would execute)"
