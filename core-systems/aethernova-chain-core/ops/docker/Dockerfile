# syntax=docker/dockerfile:1.7
# Официальные ссылки (проверяемость):
# BuildKit frontend & cache mounts: https://docs.docker.com/build/buildkit/
# Dockerfile best practices:       https://docs.docker.com/build/building/best-practices/
# HEALTHCHECK:                     https://docs.docker.com/engine/reference/builder/#healthcheck
# OCI Labels (annotations):        https://github.com/opencontainers/image-spec/blob/main/annotations.md
# cargo-chef (Rust deps cache):    https://github.com/LukeMathWalker/cargo-chef
# Non-root user in containers:     https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user

###############################################
#                COMMON ARGS
###############################################
ARG DEBIAN_VERSION=bookworm
ARG RUST_VERSION=1.79
ARG APP_NAME=aethernova-node
ARG APP_PORT=30333
ARG APP_HOME=/app
ARG RUST_PROFILE=release
ARG RUSTFLAGS=""
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown
ARG VERSION=0.0.0

###############################################
#           RUST CHEF (dependency plan)
###############################################
FROM rust:${RUST_VERSION}-${DEBIAN_VERSION} AS rust-chef
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config clang make cmake git ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /chef
# cargo-chef установим для оптимального кеширования зависимостей
RUN cargo install cargo-chef --locked

###############################################
#           RUST PLANNER (compute deps graph)
###############################################
FROM rust-chef AS planner
WORKDIR /src
# Копируем только манифесты для детерминированного плана зависимостей
# Предполагается стандартная структура Rust-проекта:
#   /Cargo.toml, /Cargo.lock, /crates/*/Cargo.toml
# Замените пути под свой моно-репозиторий при необходимости.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# Готовим рецепт для дальнейшей сборки зависимостей
RUN cargo chef prepare --recipe-path recipe.json

###############################################
#           RUST BUILDER (build deps & app)
###############################################
FROM rust-chef AS builder
ARG RUST_PROFILE
ARG RUSTFLAGS
ENV RUSTFLAGS="${RUSTFLAGS}"
WORKDIR /src

# Теплим кеш для cargo/registry и target
# ref: https://docs.docker.com/build/cache/
# hadolint ignore=DL3008
RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=cargo-git,target=/usr/local/cargo/git \
    true

# Сначала прогреваем зависимости по рецепту — стабильный кеш
COPY --from=planner /src/recipe.json ./recipe.json
RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=cargo-target,target=/src/target \
    cargo chef cook --release --recipe-path recipe.json

# Затем вносим исходники и собираем бинарь
COPY . .
# При необходимости можно добавить фичи/флаги компиляции через RUSTFLAGS/RUST_PROFILE
RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=cargo-target,target=/src/target \
    cargo build --${RUST_PROFILE}

# Выясняем фактический путь бинаря: target/release/${APP_NAME}
# Если бинарь в отдельном крейте (например, crates/node), скорректируйте COPY ниже.

###############################################
#           RUNTIME (slim, non-root)
###############################################
FROM debian:${DEBIAN_VERSION}-slim AS runtime
ARG APP_NAME
ARG APP_HOME
ARG APP_PORT
ARG GIT_COMMIT
ARG BUILD_DATE
ARG VERSION

# Базовые зависимости рантайма и CA
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates tzdata curl \
  && rm -rf /var/lib/apt/lists/*

# Создаём изолированного пользователя и директории
RUN groupadd -r app && useradd -r -g app -d ${APP_HOME} app
RUN mkdir -p ${APP_HOME}/bin ${APP_HOME}/data ${APP_HOME}/config /var/log/${APP_NAME} \
 && chown -R app:app ${APP_HOME} /var/log/${APP_NAME}

WORKDIR ${APP_HOME}

# Копируем бинарь из builder
COPY --from=builder /src/target/release/${APP_NAME} ${APP_HOME}/bin/${APP_NAME}

# Минимальные разрешения
RUN chmod 0755 ${APP_HOME}/bin/${APP_NAME}

# OCI аннотации (источник: image-spec/annotations)
# https://github.com/opencontainers/image-spec/blob/main/annotations.md
LABEL org.opencontainers.image.title="${APP_NAME}" \
      org.opencontainers.image.description="Aethernova Chain Core node" \
      org.opencontainers.image.source="https://example.com/aethernova-chain-core" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.licenses="Proprietary"

ENV RUST_LOG=info \
    APP_DATA_DIR=${APP_HOME}/data \
    APP_CONFIG=${APP_HOME}/config/config.toml \
    APP_PORT=${APP_PORT}

EXPOSE ${APP_PORT}/tcp

# Запускаемся от non-root
USER app:app

# HEALTHCHECK без /bin/sh (используем exec-форму curl из рантайма)
# Документация: https://docs.docker.com/engine/reference/builder/#healthcheck
HEALTHCHECK --interval=30s --timeout=5s --retries=5 --start-period=20s \
  CMD curl -fsS "http://127.0.0.1:${APP_PORT}/health" || exit 1

# Аргументы запуска. Добавьте свои флаги и конфиги.
ENTRYPOINT ["./bin/aethernova-node"]
CMD ["--data-dir","/app/data","--config","/app/config/config.toml","--rpc-port","30333"]

###############################################
#           OPTIONAL: GO NODE (delve build)
###############################################
# Пример альтернативной сборки Go-узла (если в репозитории есть реализация на Go).
# Оставлено как отдельная цель, собираем с:  docker build --target go-runtime ...
FROM golang:1.22-${DEBIAN_VERSION} AS go-builder
ARG APP_HOME
ARG APP_NAME
WORKDIR /src
# Кешируем модули
RUN --mount=type=cache,id=gomod,target=/go/pkg/mod \
    --mount=type=cache,id=gocache,target=/root/.cache/go-build \
    true
COPY go.mod go.sum ./
RUN --mount=type=cache,id=gomod,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,id=gocache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /tmp/${APP_NAME} ./cmd/chain-node

FROM gcr.io/distroless/static-debian12 AS go-runtime
ARG APP_HOME
ARG APP_NAME
ARG APP_PORT
WORKDIR ${APP_HOME}
COPY --from=go-builder /tmp/${APP_NAME} ./bin/${APP_NAME}
USER 65532:65532
EXPOSE ${APP_PORT}
# HEALTHCHECK отсутствует (distroless без shell/curl); используйте оркестраторский L7-health.
ENTRYPOINT ["./bin/aethernova-node"]
CMD ["--data-dir","/app/data","--rpc-port","30333"]

###############################################
#           OPTIONAL: DEBUG RUNTIME
###############################################
# Для отладки можно собрать облегчённый образ с busybox и шеллом.
# Не используйте в продакшн.
FROM ${DEBIAN_VERSION}-slim AS debug-runtime
ARG APP_NAME
ARG APP_HOME
WORKDIR ${APP_HOME}
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl iproute2 net-tools \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/${APP_NAME} ${APP_HOME}/bin/${APP_NAME}
USER root
ENTRYPOINT ["bash","-lc","./bin/aethernova-node --data-dir=/app/data --config=/app/config/config.toml --rpc-port=30333"]
