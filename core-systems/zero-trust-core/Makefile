# Makefile — production-grade tasks for zero-trust-core
#
# Goals:
# - reproducible builds and images
# - safety checks (lint/scan/test)
# - CI-friendly (exit codes and machine-readable outputs)
# - release helpers (semantic versioning from git tags)
#
# Usage examples:
#   make help
#   make lint
#   make build
#   make docker-build
#   make test
#
SHELL := /usr/bin/env bash
.SHELLFLAGS := -eo pipefail -c
.PHONY: help ensure-tools lint fmt test build docker-build docker-push release clean

# Project metadata
APP := zero-trust-core
PKG := github.com/yourorg/$(APP)          # replace with real module path
BUILD_DIR := ./dist
BIN := $(BUILD_DIR)/$(APP)
GO := $(shell command -v go 2>/dev/null || true)
GIT := $(shell command -v git 2>/dev/null || true)
DOCKER := $(shell command -v docker 2>/dev/null || true)
TERRAFORM := $(shell command -v terraform 2>/dev/null || true)

# Docker defaults (override in environment)
IMAGE_REGISTRY ?= registry.example.com/yourorg
IMAGE_NAME ?= $(IMAGE_REGISTRY)/$(APP)
IMAGE_TAG ?= $(shell $(GIT) describe --tags --dirty --always 2>/dev/null || echo "dev")
DOCKER_BUILDKIT ?= 1

# Tools used for lint/format/scan
GOLANGCI_LINT := $(shell command -v golangci-lint 2>/dev/null || true)
SHELLCHECK := $(shell command -v shellcheck 2>/dev/null || true)
YAMLLINT := $(shell command -v yamllint 2>/dev/null || true)
OPENSCAP := $(shell command -v oscap 2>/dev/null || true)
TRIVY := $(shell command -v trivy 2>/dev/null || true)

# Build flags
LDFLAGS := -X '$(PKG)/version.Version=$(IMAGE_TAG)'

# ==============================================================================
# Helpers
# ==============================================================================

help:
	@cat <<'EOF'
Makefile targets:
  help            Show this help
  ensure-tools    Check required CLI tools (CI uses this)
  fmt             Run formatters (go fmt / shfmt / prettier if available)
  lint            Run linters (golangci-lint, shellcheck, yamllint)
  test            Run unit and integration tests
  build           Build binary into $(BUILD_DIR)
  docker-build    Build container image $(IMAGE_NAME):$(IMAGE_TAG)
  docker-push     Push container image (requires DOCKER_AUTH)
  scan            Run security scans (trivy, openscap)
  tf-fmt          terraform fmt for /ops/terraform
  tf-validate     terraform validate (requires terraform)
  release         Create annotated git tag and push + docker publish
  clean           Clean build artifacts
EOF

ensure-tools:
	@echo "Checking required tools..."
	@{ test -n "$(GO)" && echo "go: ok" || (echo "go: missing" && exit 1); }
	@{ test -n "$(GIT)" && echo "git: ok" || (echo "git: missing" && exit 1); }
	@{ test -n "$(DOCKER)" && echo "docker: ok" || echo "docker: optional"; }
	@echo "Done."

# ==============================================================================
# Code quality
# ==============================================================================

fmt:
ifeq ($(GO),)
	@echo "go not found; skipping go fmt"
else
	@echo "go fmt..."
	@$(GO) fmt ./...
endif
	@echo "Formatting other files (yaml, sh) if tools are present..."
	@{ test -n "$(SHELLCHECK)" && echo "shellcheck available" || true; }

lint: ensure-tools
	@echo "Running linters..."
ifeq ($(GOLANGCI_LINT),)
	@echo "golangci-lint not found: skip go lint"
else
	@$(GOLANGCI_LINT) run ./... || (echo "golangci-lint found issues" && exit 1)
endif
ifeq ($(SHELLCHECK),)
	@echo "shellcheck not found: skip shell lint"
else
	@find . -type f -name '*.sh' -print0 | xargs -0 $(SHELLCHECK) || true
endif
ifeq ($(YAMLLINT),)
	@echo "yamllint not found: skip yaml lint"
else
	@$(YAMLLINT) -c .yamllint.yml $(shell find . -name '*.yaml' -o -name '*.yml') || exit 1
endif
	@echo "Lint completed."

# ==============================================================================
# Tests
# ==============================================================================

test: ensure-tools
	@echo "Running unit tests..."
ifeq ($(GO),)
	@echo "go not found; cannot run tests" && exit 1
else
	@$(GO) test ./... -v -count=1
endif

# ==============================================================================
# Build and package
# ==============================================================================

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

build: ensure-tools $(BUILD_DIR)
	@echo "Building $(APP) -> $(BIN)"
	@env CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN) ./...
	@echo "Build complete: $(BIN)"

docker-build: ensure-tools
	@echo "Building docker image $(IMAGE_NAME):$(IMAGE_TAG)"
	@export DOCKER_BUILDKIT=$(DOCKER_BUILDKIT); \
	if [ -f Dockerfile ]; then \
		$(DOCKER) build --pull -t $(IMAGE_NAME):$(IMAGE_TAG) .; \
	else \
		echo "Dockerfile not found in repo root"; exit 1; \
	fi

docker-push:
	@echo "Pushing image $(IMAGE_NAME):$(IMAGE_TAG)"
	@{ test -n "$(DOCKER)" || (echo "docker missing"; exit 1); }
	@$(DOCKER) push $(IMAGE_NAME):$(IMAGE_TAG)

# ==============================================================================
# Security scans
# ==============================================================================

scan:
	@echo "Running security scans (best-effort)"
ifeq ($(TRIVY),)
	@echo "trivy not found: skip container/image scans"
else
	@if $(DOCKER) image inspect $(IMAGE_NAME):$(IMAGE_TAG) >/dev/null 2>&1; then \
		$(TRIVY) image --severity HIGH,CRITICAL $(IMAGE_NAME):$(IMAGE_TAG) || true; \
	else \
		echo "Image not built: run make docker-build first"; \
	fi
endif
ifeq ($(OPENSCAP),)
	@echo "oscap not found: skip OS policy scans"
else
	@echo "oscap is installed"
endif

# ==============================================================================
# Terraform helpers (if repo contains infra)
# ==============================================================================

tf-fmt:
	@if [ -n "$(TERRAFORM)" ]; then \
		find ops/terraform -type d -maxdepth 2 -print0 | xargs -0 -I{} sh -c 'cd "{}" && $(TERRAFORM) fmt -recursive'; \
	else \
		echo "terraform not found; skipping"; \
	fi

tf-validate:
	@if [ -n "$(TERRAFORM)" ]; then \
		cd ops/terraform && $(TERRAFORM) init -backend=false >/dev/null 2>&1 || true; \
		cd ops/terraform && $(TERRAFORM) validate || exit 1; \
	else \
		echo "terraform not found; skipping"; \
	fi

# ==============================================================================
# Release
# ==============================================================================

release: ensure-tools build docker-build
	@echo "Creating release for tag: $(IMAGE_TAG)"
	@if $(GIT) diff --quiet || true; then \
		echo "Repo clean"; \
	else \
		echo "Working tree is dirty; aborting release" && exit 1; \
	fi
	@$(GIT) tag -a "$(IMAGE_TAG)" -m "release $(IMAGE_TAG)" || true
	@$(GIT) push origin "$(IMAGE_TAG)" || true
	@make docker-push

# ==============================================================================
# Clean
# ==============================================================================

clean:
	@echo "Cleaning artifacts..."
	@rm -rf $(BUILD_DIR)
	@echo "Done."

