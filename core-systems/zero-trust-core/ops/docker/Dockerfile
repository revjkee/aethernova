# syntax=docker/dockerfile:1.7-labs

############################
# Stage 0: base (common)
############################
ARG PYTHON_VERSION=3.12
FROM python:${PYTHON_VERSION}-slim AS base

# System hardening + locales (en_US.UTF-8) + tini for PID1
ENV DEBIAN_FRONTEND=noninteractive
RUN --mount=type=cache,target=/var/cache/apt \
    set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      tini ca-certificates tzdata libstdc++6 \
    ; \
    rm -rf /var/lib/apt/lists/*

# Ensure UTF-8 and predictable time zone
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC

# Python runtime hardening
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Create non-root user and group
ARG APP_UID=10001
ARG APP_GID=10001
RUN set -eux; \
    groupadd --gid "${APP_GID}" app || true; \
    useradd  --uid "${APP_UID}" --gid "${APP_GID}" --home-dir /app --create-home --shell /usr/sbin/nologin app

WORKDIR /app

############################
# Stage 1: builder (deps)
############################
FROM base AS builder

# Build tooling (gcc removed after wheel build avoidance; for pure python usually not needed)
RUN --mount=type=cache,target=/var/cache/apt \
    set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends build-essential git; \
    rm -rf /var/lib/apt/lists/*

# Use a virtualenv to keep runtime clean
ENV VENV=/opt/venv
RUN python -m venv "$VENV"
ENV PATH="$VENV/bin:$PATH"

# Copy dependency manifests first to leverage layer caching.
# Supported options (provide любые два файла, лишние игнорируются):
#  - requirements.txt (c hash-ами)
#  - requirements.lock (pip-compile output)
#  - pyproject.toml + requirements.lock (pep518 + lock)
#  - constraints.txt (для пиннинга)
COPY ops/docker/requirements.lock requirements.lock
COPY ops/docker/requirements.txt requirements.txt
COPY ops/docker/constraints.txt constraints.txt

# Install deps with strongest guarantees when есть lock с хешами
# Порядок:
#   1) requirements.lock (pip-compile, с --generate-hashes)
#   2) requirements.txt (если содержит --hash)
#   3) fallback: requirements.txt без хешей (не рекомендуется)
RUN set -eux; \
    if [ -s requirements.lock ]; then \
        python -m pip install --upgrade pip wheel; \
        pip install --require-hashes -r requirements.lock; \
    elif [ -s requirements.txt ] && grep -q -- "--hash=" requirements.txt; then \
        python -m pip install --upgrade pip wheel; \
        pip install --require-hashes -r requirements.txt; \
    elif [ -s requirements.txt ]; then \
        python -m pip install --upgrade pip wheel; \
        pip install -r requirements.txt ${PIP_EXTRA_INDEX_ARGS:-}; \
    else \
        echo "No requirements provided; proceeding with stdlib-only."; \
    fi

# Optionally install uvicorn/gunicorn if not in requirements
RUN set -eux; \
    python - <<'PY' || true
import importlib, sys
for pkg in ("uvicorn",):
    try: importlib.import_module(pkg)
    except ImportError: print(pkg)
PY \
    | xargs -r pip install "uvicorn[standard]"

############################
# Stage 2: runtime
############################
FROM base AS runtime

# Virtualenv from builder
ENV VENV=/opt/venv
COPY --from=builder ${VENV} ${VENV}
ENV PATH="${VENV}/bin:${PATH}"

# Copy source code (adjust ignore via .dockerignore)
# Structure expected:
#   zero-trust-core/
#     avm_core/...
#     zero_trust_core/...
#     ops/docker/...
COPY . /app

# App metadata and OCI labels
ARG BUILD_REVISION=unknown
ARG BUILD_DATE=unknown
ARG VCS_URL=unknown
LABEL org.opencontainers.image.title="zero-trust-core" \
      org.opencontainers.image.description="Zero Trust Core (API + Scheduler) - hardened Python container" \
      org.opencontainers.image.source="${VCS_URL}" \
      org.opencontainers.image.revision="${BUILD_REVISION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.licenses="Apache-2.0"

# Drop to non-root early
USER app:app

# Default env (override at runtime)
ENV APP_ENV=production \
    OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317 \
    UVICORN_WORKERS=1 \
    UVICORN_HOST=0.0.0.0 \
    UVICORN_PORT=8080

# Expose for API
EXPOSE 8080

# Healthcheck (customize path/module accordingly)
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
  CMD python - <<'PY' || exit 1
import os,sys,urllib.request
url=os.environ.get("HEALTH_URL","http://127.0.0.1:%s/healthz"%os.environ.get("UVICORN_PORT","8080"))
try:
    with urllib.request.urlopen(url, timeout=2) as r:
        sys.exit(0 if 200 <= r.status < 500 else 1)
except Exception:
    sys.exit(1)
PY

# Read-only FS by default; app can write to /tmp and $HOME/.cache
VOLUME ["/tmp"]
ENV PYTHONPYCACHEPREFIX=/tmp/pycache

# Secure default entrypoint via tini
ENTRYPOINT ["/usr/bin/tini","-g","--"]

# Start mode via CMD:
#  - api:      uvicorn avm_core.engine.api.app:app
#  - scheduler: python -m avm_core.engine.scheduler
# Override with: docker run ... --env START_MODE=scheduler
ENV START_MODE=api

CMD ["/bin/sh","-c", "\
  if [ \"$START_MODE\" = \"scheduler\" ]; then \
      exec python -m avm_core.engine.scheduler; \
  else \
      exec python -m uvicorn avm_core.engine.api.app:app --host ${UVICORN_HOST} --port ${UVICORN_PORT} --workers ${UVICORN_WORKERS}; \
  fi \
"]

############################
# Stage 3 (optional): distroless runtime
############################
# For an even smaller attack surface, uncomment this stage and set TARGET=distroless at build time.
# FROM gcr.io/distroless/python3-debian12 AS distroless
# COPY --from=runtime /opt/venv /opt/venv
# COPY --from=runtime /usr/bin/tini /usr/bin/tini
# COPY --from=runtime /app /app
# ENV PATH="/opt/venv/bin:${PATH}" APP_ENV=production UVICORN_HOST=0.0.0.0 UVICORN_PORT=8080 UVICORN_WORKERS=1 START_MODE=api
# USER 10001:10001
# EXPOSE 8080
# ENTRYPOINT ["/usr/bin/tini","-g","--"]
# CMD ["/bin/sh","-c","if [ \"$START_MODE\" = \"scheduler\" ]; then exec python -m avm_core.engine.scheduler; else exec python -m uvicorn avm_core.engine.api.app:app --host ${UVICORN_HOST} --port ${UVICORN_PORT} --workers ${UVICORN_WORKERS}; fi"]

