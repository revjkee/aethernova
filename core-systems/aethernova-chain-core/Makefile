# =============================================================================
# Aethernova Chain Core — Industrial Makefile
# Path: aethernova-chain-core/Makefile
# =============================================================================

# -------- Shell & safety ------------------------------------------------------
SHELL := /usr/bin/env bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c
MAKEFLAGS += --no-builtin-rules
MAKEFLAGS += --warn-undefined-variables
.DEFAULT_GOAL := help

# -------- Project metadata ----------------------------------------------------
PROJECT          ?= aethernova-chain-core
REGISTRY         ?= ghcr.io/aethernova
IMAGE_NAME       ?= $(PROJECT)
DOCKERFILE       ?= Dockerfile
BUILDPLATFORM    ?= linux/amd64
TARGETPLATFORM   ?= linux/amd64

# Select implementation language: rust | go
CHAIN_LANG       ?= rust

# Git/version info
GIT_COMMIT       := $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH       := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
GIT_TAG          := $(shell git describe --tags --abbrev=0 2>/dev/null || echo "")
VERSION_FILE     ?= VERSION
ifneq ("$(GIT_TAG)","")
  VERSION        := $(GIT_TAG)
else
  VERSION        := $(shell [ -f "$(VERSION_FILE)" ] && cat "$(VERSION_FILE)" || echo "0.0.0-dev")
endif

# Time & reproducible builds
BUILD_DATE       := $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
SOURCE_DATE_EPOCH:= $(shell date -u +%s)
export SOURCE_DATE_EPOCH

# Load .env if present
ifneq ("$(wildcard .env)","")
  include .env
  export
endif

# -------- Colors --------------------------------------------------------------
Y  := \033[33m
G  := \033[32m
B  := \033[34m
R  := \033[31m
N  := \033[0m

# -------- Tools discovery (soft checks) --------------------------------------
CARGO            ?= cargo
RUSTC            ?= rustc
GO               ?= go
GOLANGCI_LINT    ?= golangci-lint
BUF              ?= buf
PROTOC           ?= protoc
TRIVY            ?= trivy
SYFT             ?= syft
COSIGN           ?= cosign
DOCKER           ?= docker
DOCKER_BUILDX    ?= docker buildx

# -------- Directories ---------------------------------------------------------
BIN_DIR          ?= bin
BUILD_DIR        ?= build
COVER_DIR        ?= $(BUILD_DIR)/coverage
SBOM_DIR         ?= sbom
PROTO_DIR        ?= proto
GEN_DIR          ?= gen

# Create dirs lazily
$(shell mkdir -p $(BIN_DIR) $(BUILD_DIR) $(COVER_DIR) $(SBOM_DIR) $(GEN_DIR) >/dev/null 2>&1 || true)

# -------- Helper macros -------------------------------------------------------
define _print_kv
	@printf "  $(B)%-16s$(N) %s\n" "$(1):" "$(2)"
endef

define _need_tool
	@command -v $(1) >/dev/null 2>&1 || { echo -e "$(R)Missing tool: $(1)$(N)"; exit 1; }
endef

# =============================================================================
# Help
# =============================================================================
.PHONY: help
help: ## Показать справку по командам
	@echo -e "$(G)$(PROJECT) — Make targets$(N)"
	@echo
	@echo "Основные:"
	@echo "  make verify             — Полный цикл: fmt, lint, build, test, coverage"
	@echo "  make docker-build       — Сборка контейнера"
	@echo "  make docker-scan        — Скан образа Trivy"
	@echo "  make docker-push        — Публикация образа"
	@echo "  make docker-sbom        — SBOM образа Syft (SPDX/JSON)"
	@echo "  make proto              — Генерация gRPC/Protobuf (buf/protoc)"
	@echo "  make release TAG=vX.Y.Z — Создать git-тег релиза и записать VERSION"
	@echo
	@echo "Язык реализации (по умолчанию rust): CHAIN_LANG=rust|go"
	@echo
	@$(call _print_kv,Project,$(PROJECT))
	@$(call _print_kv,Version,$(VERSION))
	@$(call _print_kv,Branch,$(GIT_BRANCH))
	@$(call _print_kv,Commit,$(GIT_COMMIT))
	@$(call _print_kv,BuildDate,$(BUILD_DATE))
	@echo

# =============================================================================
# Common aggregate targets
# =============================================================================
.PHONY: verify fmt lint build test coverage clean
verify: fmt lint build test coverage ## Полная проверка проекта

fmt: ## Форматирование кода
ifeq ($(CHAIN_LANG),rust)
	$(call _need_tool,$(CARGO))
	$(CARGO) fmt --all
else ifeq ($(CHAIN_LANG),go)
	$(call _need_tool,$(GO))
	$(GO) fmt ./...
else
	@echo -e "$(R)Unknown CHAIN_LANG=$(CHAIN_LANG). Use rust|go$(N)"; exit 1
endif

lint: ## Линт кода
ifeq ($(CHAIN_LANG),rust)
	$(call _need_tool,$(CARGO))
	$(CARGO) clippy --all-targets --all-features -- -D warnings
else ifeq ($(CHAIN_LANG),go)
	$(call _need_tool,$(GOLANGCI_LINT))
	$(GOLANGCI_LINT) run ./...
else
	@echo -e "$(R)Unknown CHAIN_LANG=$(CHAIN_LANG). Use rust|go$(N)"; exit 1
endif

build: ## Сборка проекта (release)
ifeq ($(CHAIN_LANG),rust)
	$(call _need_tool,$(CARGO))
	RUSTFLAGS="-C link-arg=-s" $(CARGO) build --release
else ifeq ($(CHAIN_LANG),go)
	$(call _need_tool,$(GO))
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		$(GO) build -trimpath -ldflags "-s -w \
		-X main.version=$(VERSION) -X main.commit=$(GIT_COMMIT) -X main.date=$(BUILD_DATE)" \
		-o $(BUILD_DIR)/$(PROJECT) ./...
else
	@echo -e "$(R)Unknown CHAIN_LANG=$(CHAIN_LANG). Use rust|go$(N)"; exit 1
endif

test: ## Тесты
ifeq ($(CHAIN_LANG),rust)
	$(call _need_tool,$(CARGO))
	$(CARGO) test --all --all-features -- --nocapture
else ifeq ($(CHAIN_LANG),go)
	$(call _need_tool,$(GO))
	$(GO) test ./... -count=1 -race -v
else
	@echo -e "$(R)Unknown CHAIN_LANG=$(CHAIN_LANG). Use rust|go$(N)"; exit 1
endif

coverage: ## Покрытие тестами (отчет в build/coverage)
ifeq ($(CHAIN_LANG),rust)
	$(call _need_tool,$(CARGO))
	@echo -e "$(Y)Rust coverage: installing llvm-tools-preview may be required$(N)"
	# Using cargo tarpaulin if available; fallback message if not installed
	@if command -v cargo-tarpaulin >/dev/null 2>&1; then \
		cargo tarpaulin -o Html --output-dir $(COVER_DIR); \
	else \
		echo "Install cargo-tarpaulin for coverage: https://github.com/xd009642/tarpaulin"; \
	fi
else ifeq ($(CHAIN_LANG),go)
	$(call _need_tool,$(GO))
	$(GO) test ./... -coverprofile=$(COVER_DIR)/coverage.out
	$(GO) tool cover -html=$(COVER_DIR)/coverage.out -o $(COVER_DIR)/coverage.html
	@echo -e "$(G)Coverage report: $(COVER_DIR)/coverage.html$(N)"
else
	@echo -e "$(R)Unknown CHAIN_LANG=$(CHAIN_LANG). Use rust|go$(N)"; exit 1
endif

clean: ## Очистка артефактов сборки
	@echo -e "$(Y)Cleaning...$(N)"
	rm -rf $(BUILD_DIR) $(COVER_DIR) $(GEN_DIR) || true
ifeq ($(CHAIN_LANG),rust)
	@if command -v $(CARGO) >/dev/null 2>&1; then $(CARGO) clean; fi
endif

# =============================================================================
# Protobuf / gRPC
# =============================================================================
.PHONY: proto
proto: ## Генерация из Protobuf (buf с fallback на protoc)
ifneq ("$(wildcard $(PROTO_DIR))","")
	@if command -v $(BUF) >/dev/null 2>&1; then \
		$(BUF) generate; \
	elif command -v $(PROTOC) >/dev/null 2>&1; then \
		echo -e "$(Y)buf not found — using protoc$(N)"; \
		mkdir -p $(GEN_DIR); \
		find $(PROTO_DIR) -name '*.proto' -print0 | xargs -0 -I{} $(PROTOC) \
			--proto_path=$(PROTO_DIR) \
			--go_out=$(GEN_DIR) --go-grpc_out=$(GEN_DIR) \
			--python_out=$(GEN_DIR) --grpc-python_out=$(GEN_DIR) \
			{}; \
	else \
		echo -e "$(R)Neither buf nor protoc found$(N)"; exit 1; \
	fi
else
	@echo -e "$(Y)No proto directory found: $(PROTO_DIR)$(N)"
endif

# =============================================================================
# Security & Compliance
# =============================================================================
.PHONY: sec-audit
sec-audit: ## Быстрый security-аудит зависимостей
ifeq ($(CHAIN_LANG),rust)
	@if command -v cargo-audit >/dev/null 2>&1; then \
		cargo audit; \
	else \
		echo -e "$(Y)cargo-audit not installed: https://github.com/rustsec/rustsec/tree/main/cargo-audit$(N)"; \
	fi
else ifeq ($(CHAIN_LANG),go)
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo -e "$(Y)govulncheck not installed: https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck$(N)"; \
	fi
endif

# =============================================================================
# Docker lifecycle
# =============================================================================
IMAGE_TAG ?= $(VERSION)
IMAGE     := $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)

.PHONY: docker-build docker-scan docker-push docker-sbom docker-run
docker-build: ## Сборка контейнера (buildx)
	$(call _need_tool,$(DOCKER))
	$(DOCKER_BUILDX) build \
	  --platform $(TARGETPLATFORM) \
	  -f $(DOCKERFILE) \
	  --build-arg PROJECT=$(PROJECT) \
	  --build-arg VERSION=$(VERSION) \
	  --build-arg GIT_COMMIT=$(GIT_COMMIT) \
	  --build-arg GIT_BRANCH=$(GIT_BRANCH) \
	  --build-arg BUILD_DATE=$(BUILD_DATE) \
	  -t $(IMAGE) \
	  --load \
	  .

docker-run: ## Локальный запуск контейнера
	$(call _need_tool,$(DOCKER))
	$(DOCKER) run --rm -it -p 26657:26657 -p 26656:26656 --name $(PROJECT) $(IMAGE)

docker-push: ## Публикация контейнера
	$(call _need_tool,$(DOCKER))
	$(DOCKER) push $(IMAGE)

docker-scan: ## Скан уязвимостей Trivy
	@if command -v $(TRIVY) >/dev/null 2>&1; then \
		$(TRIVY) image --scanners vuln,secret,config $(IMAGE); \
	else \
		echo -e "$(Y)trivy not installed: https://aquasecurity.github.io/trivy/$(N)"; \
	fi

docker-sbom: ## Генерация SBOM (Syft SPDX JSON)
	@if command -v $(SYFT) >/dev/null 2>&1; then \
		mkdir -p $(SBOM_DIR); \
		$(SYFT) $(IMAGE) -o spdx-json > $(SBOM_DIR)/$(PROJECT)-$(IMAGE_TAG)-sbom.spdx.json; \
		echo -e "$(G)SBOM written: $(SBOM_DIR)/$(PROJECT)-$(IMAGE_TAG)-sbom.spdx.json$(N)"; \
	else \
		echo -e "$(Y)syft not installed: https://github.com/anchore/syft$(N)"; \
	fi

# =============================================================================
# Release management
# =============================================================================
.PHONY: release tag verify-release sign-image
release: ## Создать git-тег релиза: make release TAG=vX.Y.Z
	@[ -n "$(TAG)" ] || { echo -e "$(R)Specify TAG=vX.Y.Z$(N)"; exit 1; }
	@echo "$(TAG)" > $(VERSION_FILE)
	git add $(VERSION_FILE)
	git commit -m "chore(release): $(TAG)" || true
	git tag -a "$(TAG)" -m "Release $(TAG)"
	@echo -e "$(G)Tagged $(TAG)$(N)"

tag: release ## Синоним release

verify-release: ## Проверка, что VERSION совпадает с последним тегом
	@LAST=$$(git describe --tags --abbrev=0 2>/dev/null || echo ""); \
	if [ -z "$$LAST" ]; then echo -e "$(Y)No tags found$(N)"; exit 0; fi; \
	V=$$(cat $(VERSION_FILE)); \
	if [ "$$LAST" != "$$V" ]; then \
		echo -e "$(R)VERSION ($$V) != latest tag ($$LAST)$(N)"; exit 1; \
	else \
		echo -e "$(G)Release ok: $$V$(N)"; \
	fi

sign-image: ## Подписать образ cosign (keyless или key)
	@if command -v $(COSIGN) >/dev/null 2>&1; then \
		$(COSIGN) sign --yes $(IMAGE); \
	else \
		echo -e "$(Y)cosign not installed: https://docs.sigstore.dev/cosign/$(N)"; \
	fi

# =============================================================================
# Convenience meta targets
# =============================================================================
.PHONY: precommit ci
precommit: fmt lint test ## Набор для pre-commit
ci: verify docker-build docker-scan docker-sbom ## Набор для CI

# =============================================================================
# Diagnostics
# =============================================================================
.PHONY: doctor env
doctor: ## Проверка наличия ключевых инструментов
	@echo -e "$(B)Checking toolchain...$(N)"
	@for t in git $(DOCKER) $(TRIVY) $(SYFT) $(COSIGN); do \
		if command -v $$t >/dev/null 2>&1; then echo "  ok  $$t"; else echo "  miss $$t"; fi; \
	done
ifeq ($(CHAIN_LANG),rust)
	@for t in $(CARGO) $(RUSTC); do \
		if command -v $$t >/dev/null 2>&1; then echo "  ok  $$t"; else echo "  miss $$t"; fi; \
	done
else ifeq ($(CHAIN_LANG),go)
	@for t in $(GO) $(GOLANGCI_LINT); do \
		if command -v $$t >/dev/null 2>&1; then echo "  ok  $$t"; else echo "  miss $$t"; fi; \
	done
endif
	@echo -e "$(G)Done$(N)"

env: ## Показать ключевые переменные окружения
	@$(call _print_kv,CHAIN_LANG,$(CHAIN_LANG))
	@$(call _print_kv,VERSION,$(VERSION))
	@$(call _print_kv,IMAGE,$(IMAGE))
	@$(call _print_kv,BUILD_DIR,$(BUILD_DIR))
	@$(call _print_kv,SBOM_DIR,$(SBOM_DIR))

# =============================================================================
# End
# =============================================================================
