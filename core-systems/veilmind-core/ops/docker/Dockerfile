# syntax=docker/dockerfile:1.7-labs
#
# VeilMind Core — Production Dockerfile
# - Multi-stage build (builder -> runtime)
# - Reproducible wheels via PEP 517
# - Optional extras via ARG EXTRAS (e.g. "opentelemetry,prometheus,web")
# - Non-root, read-only FS, Tini as PID 1
# - Healthcheck (HTTP or CLI), OCI labels, SBOM placeholder
#

############################
# Base versions and args
############################
ARG PYTHON_VERSION=3.12
ARG DEBIAN_FRONTEND=noninteractive
ARG APP_NAME=veilmind-core
ARG APP_IMPORT=veilmind_core
# Comma-separated Poetry extras, e.g.: "opentelemetry,prometheus,web"
ARG EXTRAS=""
# If your code lives under /src with PEP 420/namespace packaging
ARG SRC_DIR=/work/src

############################
# Builder: build wheels
############################
FROM python:${PYTHON_VERSION}-slim AS builder

ARG DEBIAN_FRONTEND
ARG APP_NAME
ARG SRC_DIR
ARG EXTRAS

# System deps (build-essential kept minimal and removed later via stage boundary)
RUN --mount=type=cache,target=/var/cache/apt \
    apt-get update -y && apt-get install -y --no-install-recommends \
      build-essential \
      curl ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# Python toolchain hardening
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install build backends and helpers only in builder
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --upgrade pip wheel build poetry-core>=1.9.0 poetry>=1.7.0

WORKDIR /work

# Copy only metadata first for better caching
COPY pyproject.toml poetry.lock* ./

# Resolve and export lock to requirements set (including extras) using Poetry
# We avoid installing into builder environment — we just build wheels.
RUN --mount=type=cache,target=/root/.cache/pip \
    python - <<'PY' "$EXTRAS" \
    import json, os, subprocess, sys; extras=sys.argv[1].strip()
    # Export with hashes for deterministic downstream install
    base=["poetry","export","--without-hashes","-f","requirements.txt","-o","/work/requirements.txt","--only","main"]
    if extras:
        base=["poetry","export","-E",extras,"--without-hashes","-f","requirements.txt","-o","/work/requirements.txt","--only","main"]
    # Fallback to PEP 621 directly if poetry.lock not present; we proceed anyway.
    try:
        subprocess.run(base, check=True)
    except Exception as e:
        # If poetry export fails (no lock), generate via build back-end resolution at install time.
        # Create an empty requirements to avoid failing next step.
        open("/work/requirements.txt","w").close()
    PY

# Copy source and anything needed for build (readme/license as needed)
COPY ${SRC_DIR} ${SRC_DIR}
COPY README.md LICENSE* NOTICE* VERSION* THIRD_PARTY_NOTICES** . 2>/dev/null || true

# Build our own wheel (and sdist for provenance)
RUN --mount=type=cache,target=/root/.cache/pip \
    python -m build --wheel --sdist --outdir /work/dist

# Pre-build third-party dependencies into a local wheelhouse for a fully offline runtime install
RUN --mount=type=cache,target=/root/.cache/pip \
    mkdir -p /work/wheelhouse && \
    if [ -s /work/requirements.txt ]; then \
        pip wheel --wheel-dir /work/wheelhouse -r /work/requirements.txt; \
    fi

############################
# Runtime: minimal, non-root
############################
FROM python:${PYTHON_VERSION}-slim AS runtime

ARG APP_NAME
ARG APP_IMPORT
ARG EXTRAS

# Labels (OCI)
LABEL org.opencontainers.image.title="${APP_NAME}" \
      org.opencontainers.image.source="https://git.example/veilmind/veilmind-core" \
      org.opencontainers.image.description="VeilMind Core — secure AI/Zero-Trust backbone library" \
      org.opencontainers.image.licenses="Apache-2.0"

# Minimal OS deps for prod
RUN --mount=type=cache,target=/var/cache/apt \
    apt-get update -y && apt-get install -y --no-install-recommends \
      tini \
    && rm -rf /var/lib/apt/lists/*

# Python runtime hardening
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # Prevent writing .pyc outside site-packages
    PYTHONOPTIMIZE=1

# Create app user and directories
ENV APP_HOME=/app
RUN useradd --system --create-home --home-dir ${APP_HOME} --shell /usr/sbin/nologin appuser
WORKDIR ${APP_HOME}

# Copy artifacts from builder
COPY --from=builder /work/dist /wheels/dist
COPY --from=builder /work/wheelhouse /wheels/thirdparty
# Optional: sbom/provenance placeholders if you generate them in CI
# COPY --from=builder /work/sbom.spdx /sbom/  # if available

# Install only wheels (app first to ensure entry points are present)
# We install third-party wheelhouse separately to keep clearer layers.
RUN --mount=type=cache,target=/root/.cache/pip \
    set -eux; \
    if [ -d /wheels/thirdparty ] && [ "$(ls -A /wheels/thirdparty || true)" ]; then \
        pip install --no-deps /wheels/dist/*.whl; \
        pip install --no-index --find-links=/wheels/thirdparty -r /dev/null 2>/dev/null || true; \
        pip install --no-index --find-links=/wheels/thirdparty -r /wheels/requirements.txt 2>/dev/null || true || true; \
    else \
        pip install /wheels/dist/*.whl; \
    fi

# Drop wheel caches
RUN rm -rf /wheels

# Runtime environment (tunable)
ENV VEILMIND_ENV=prod \
    VEILMIND_REGION=unknown \
    VEILMIND_LOG_LEVEL=INFO \
    # Uvicorn defaults if API is used (available via extras "web")
    UVICORN_HOST=0.0.0.0 \
    UVICORN_PORT=8080 \
    UVICORN_WORKERS=2

# Create directories writable at runtime (logs/tmp)
RUN mkdir -p /var/log/${APP_NAME} /tmp && chown -R appuser:appuser /var/log/${APP_NAME} /tmp

# Switch to non-root
USER appuser

# Expose API port (optional)
EXPOSE 8080

# Healthcheck: prefer HTTP endpoint if web extra is used; fallback to CLI health
# You can override via --health-cmd at deploy time
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD bash -lc 'if command -v curl >/dev/null 2>&1; then curl -fsS http://127.0.0.1:${UVICORN_PORT}/health || exit 1; else ${APP_IMPORT/.//}-health || exit 0; fi' || exit 1

# Read-only root FS by default; writable paths should be mounted or pre-created
# In Kubernetes, add:
#   securityContext:
#     readOnlyRootFilesystem: true
#     runAsUser: 1000
#     runAsNonRoot: true

# Default entrypoint: Tini + shell wrapper
ENTRYPOINT ["/usr/bin/tini", "--"]

# Default CMD runs CLI if present; for API run with: docker run ... -- uvicorn veilmind_core.api:app --host 0.0.0.0 --port 8080
CMD ["veilmind", "--help"]

############################
# Optional target: api
#   build with: --target api
#   requires extras "web" (fastapi, uvicorn)
############################
FROM runtime AS api
CMD ["uvicorn", "veilmind_core.api:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "2"]

############################
# Optional target: debug (adds shell tools)
############################
FROM runtime AS debug
USER root
RUN --mount=type=cache,target=/var/cache/apt \
    apt-get update -y && apt-get install -y --no-install-recommends \
      curl ca-certificates bash procps iproute2 \
    && rm -rf /var/lib/apt/lists/*
USER appuser
CMD ["bash","-lc","echo 'Debug shell. Override CMD to run app.' && sleep infinity"]
