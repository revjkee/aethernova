# omnimind-core/ops/docker/Dockerfile
# Industrial-grade, reproducible, secure Python service image for OmniMind Core.

############################
# 0) Build args (tunable)
############################
ARG PYTHON_VERSION=3.11
ARG BASE_IMAGE=python:${PYTHON_VERSION}-slim
ARG UV_VERSION=0.4.20
ARG APP_NAME=omnimind-core
ARG USER_NAME=appuser
ARG USER_UID=10001
ARG USER_GID=10001

############################
# 1) Base image (common)
############################
FROM ${BASE_IMAGE} AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    # Safer defaults
    PYTHONHASHSEED=0

# Minimal locales/timezone optional
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    curl ca-certificates tzdata \
 && rm -rf /var/lib/apt/lists/*

############################
# 2) Builder with toolchain
############################
FROM base AS builder

# System build deps; extend if you compile native wheels
# libpq-dev useful for psycopg; build-essential for manylibs; git for non-sdist deps.
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    build-essential git pkg-config libpq-dev \
 && rm -rf /var/lib/apt/lists/*

# Install uv (fast Python package manager); fallback to pip present in image
RUN pip install --upgrade pip wheel setuptools && \
    pip install "uv==${UV_VERSION}"

# Create venv in /opt/venv to make it relocatable
ENV VENV_PATH=/opt/venv
RUN python -m venv "${VENV_PATH}"
ENV PATH="${VENV_PATH}/bin:${PATH}"

# Workdir
WORKDIR /app

# Copy only dependency descriptors first for cache
# Support popular combos: uv.lock / requirements.txt / poetry.lock + pyproject.toml
COPY pyproject.toml ./
# If exists in repo — these COPYs will be cache hits; if нет — не сломают сборку
COPY uv.lock* ./ 
COPY poetry.lock* ./
COPY requirements*.txt ./

# Resolve & install deps (pref: uv -> pip as fallback)
# Priority:
# 1) uv.lock  2) pyproject (uv resolver)  3) poetry.lock (via uv)  4) requirements*.txt
# All installed into VENV_PATH, no dev extras здесь (только prod)
RUN set -eux; \
    if [ -f uv.lock ] || [ -f uv.lock.json ]; then \
        uv sync --frozen --no-dev --no-editable --python ${PYTHON_VERSION}; \
    elif [ -f pyproject.toml ]; then \
        uv pip install --system --no-deps . 2>/dev/null || true; \
        uv pip install --system --requirements <(uv pip compile --quiet --generate-hashes pyproject.toml); \
    elif [ -f poetry.lock ] && [ -f pyproject.toml ]; then \
        uv pip install --system --requirements <(uv pip compile --quiet --generate-hashes pyproject.toml); \
    elif ls requirements*.txt >/dev/null 2>&1; then \
        for f in requirements*.txt; do uv pip install --system -r "$f"; done; \
    else \
        echo "No dependency files found; proceeding without preinstall."; \
    fi

# Copy source to build wheel
COPY . /app

# Build wheel and install into venv (prod mode; no editable)
RUN set -eux; \
    if [ -f pyproject.toml ]; then \
        pip wheel --no-deps --no-build-isolation -w /tmp/wheels .; \
        pip install --no-deps --no-cache-dir /tmp/wheels/*.whl; \
    else \
        echo "pyproject.toml not found, skipping wheel build; installing package in place"; \
        pip install --no-cache-dir .; \
    fi

############################
# 3) Runtime (slim)
############################
FROM base AS runtime

# Runtime libs only (libpq5 for psycopg; add others as needed)
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    libpq5 \
 && rm -rf /var/lib/apt/lists/*

# Create non-root user/group
RUN groupadd -g ${USER_GID} ${USER_NAME} \
 && useradd -m -u ${USER_UID} -g ${USER_GID} -s /bin/bash ${USER_NAME}

# Copy virtualenv and app code from builder
ENV VENV_PATH=/opt/venv
ENV PATH="${VENV_PATH}/bin:${PATH}"
COPY --from=builder ${VENV_PATH} ${VENV_PATH}
# Copy only necessary runtime assets; keep image small
COPY --from=builder /app /app

# Security hardening: read-only fs at runtime achievable with proper mounts; here we prep dirs
RUN mkdir -p /var/run/${APP_NAME} /var/log/${APP_NAME} \
 && chown -R ${USER_NAME}:${USER_NAME} /var/run/${APP_NAME} /var/log/${APP_NAME}

WORKDIR /app

# Environment for Gunicorn/Uvicorn FastAPI
ENV APP_MODULE="omnimind_core.main:app" \
    HOST=0.0.0.0 \
    PORT=8000 \
    WORKERS=2 \
    TIMEOUT=60 \
    LOG_LEVEL=info \
    UVICORN_WORKER_CLASS="uvicorn.workers.UvicornWorker"

# Health endpoint path expected by HEALTHCHECK
ENV HEALTHCHECK_PATH="/healthz"

# Minimal runtime Python flags
ENV PYTHONOPTIMIZE=1

# Expose service port
EXPOSE 8000

# Drop root
USER ${USER_UID}:${USER_GID}

# Healthcheck (expects FastAPI route /healthz -> 200)
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \
  CMD python - <<'PY' || exit 1
import os, sys, urllib.request
url = f"http://127.0.0.1:{os.getenv('PORT','8000')}{os.getenv('HEALTHCHECK_PATH','/healthz')}"
try:
    with urllib.request.urlopen(url, timeout=2) as r:
        sys.exit(0 if r.status == 200 else 1)
except Exception:
    sys.exit(1)
PY

# Default command: Gunicorn with Uvicorn worker
CMD ["bash", "-lc", "umask 027 && exec gunicorn \"$APP_MODULE\" -k \"$UVICORN_WORKER_CLASS\" --bind \"$HOST:$PORT\" --workers \"$WORKERS\" --timeout \"$TIMEOUT\" --log-level \"$LOG_LEVEL\" --access-logfile - --error-logfile -"]
