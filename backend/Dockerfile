# backend/Dockerfile
# Industrial-grade multi-stage Dockerfile for a FastAPI ASGI backend
# - Supports dependency sources:
#     1) requirements.txt  (preferred for CI/CD determinism)
#     2) pyproject.toml + poetry.lock (auto-export to requirements)
# - Builds wheels in a dedicated builder, installs into a clean runtime
# - Non-root user, reproducible, minimal attack surface
# - Gunicorn with uvicorn workers, sensible defaults, healthcheck
# - Python 3.12 slim; adjust as needed

############################
# 1) Base image for builder
############################
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# System deps for building common libs (psycopg, numpy, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential \
      gcc \
      curl \
      git \
      libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Working dir for dependency resolution
WORKDIR /tmp/deps

# Copy dependency manifests if present
# (Both styles supported; the RUN step will detect what's available)
# Pip style
COPY requirements.txt ./requirements.txt
COPY requirements/ ./requirements/
# Poetry style
COPY pyproject.toml ./pyproject.toml
COPY poetry.lock ./poetry.lock

# Prepare wheels directory
RUN mkdir -p /wheels

# Resolve dependencies and build wheels:
# - If requirements.txt exists -> use it directly
# - Else if pyproject.toml exists -> install poetry, export frozen requirements, then build
# - Else -> fail clearly
RUN set -eux; \
    if [ -f requirements.txt ]; then \
        echo "Using requirements.txt"; \
        pip wheel --no-binary=:all: --wheel-dir /wheels -r requirements.txt || \
        pip wheel --wheel-dir /wheels -r requirements.txt; \
    elif [ -f pyproject.toml ]; then \
        echo "Using pyproject.toml + poetry.lock (if present)"; \
        pip install --upgrade pip pipx; \
        pipx install poetry; \
        if [ -f poetry.lock ]; then \
            poetry export --without-hashes --format=requirements.txt --output /tmp/req.txt; \
        else \
            poetry export --without-hashes --format=requirements.txt --output /tmp/req.txt; \
        fi; \
        pip wheel --no-binary=:all: --wheel-dir /wheels -r /tmp/req.txt || \
        pip wheel --wheel-dir /wheels -r /tmp/req.txt; \
    else \
        echo "No dependency manifest found (requirements.txt or pyproject.toml)."; \
        exit 1; \
    fi

#################################
# 2) Runtime image (slim, nonroot)
#################################
FROM python:3.12-slim AS runtime

# Runtime env hardening & perf
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UVICORN_WORKERS=2 \
    UVICORN_PORT=8000 \
    UVICORN_HOST=0.0.0.0 \
    GUNICORN_TIMEOUT=60 \
    GUNICORN_KEEPALIVE=5 \
    GUNICORN_WORKER_CLASS=uvicorn.workers.UvicornWorker \
    PIP_NO_CACHE_DIR=1

# Minimal runtime OS deps (libpq for psycopg, curl for healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
      libpq5 \
      curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user and group
ARG APP_USER=appuser
ARG APP_UID=10001
RUN groupadd --system ${APP_USER} && \
    useradd --system --create-home --gid ${APP_USER} --uid ${APP_UID} ${APP_USER}

# Create application directory
WORKDIR /app

# Copy wheels from builder and install them
COPY --from=builder /wheels /wheels

# If your app also ships local packages, installing from wheels ensures reproducibility.
# In case extra runtime deps are needed, you can copy a frozen req file and pip install from /wheels.
# Try installing via a discovered manifest to avoid rebuilding wheels in runtime:
COPY requirements.txt /tmp/requirements.txt
COPY pyproject.toml /tmp/pyproject.toml
COPY poetry.lock /tmp/poetry.lock

RUN set -eux; \
    if [ -f /tmp/requirements.txt ]; then \
        pip install --no-index --find-links=/wheels -r /tmp/requirements.txt; \
    elif [ -f /tmp/pyproject.toml ]; then \
        # Attempt to use poetry export path from builder stage if present
        # Fallback: best-effort install from built wheels by scanning common project extras
        echo "Installing from built wheels (poetry-export was in builder)."; \
        # Install all wheels
        pip install --no-index --find-links=/wheels /wheels/*; \
    else \
        echo "No manifest in runtime; installing all built wheels."; \
        pip install --no-index --find-links=/wheels /wheels/*; \
    fi \
    && rm -rf /wheels

# Copy application source code
# Adjust paths if your backend lives elsewhere
# Expecting repo layout: backend/...
COPY . /app

# Drop privileges
USER ${APP_USER}

# Expose service port
EXPOSE 8000

# Healthcheck tries common health endpoints; if none exists, root path is used.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD sh -lc 'curl -fsS "http://127.0.0.1:${UVICORN_PORT}/health" || \
              curl -fsS "http://127.0.0.1:${UVICORN_PORT}/healthz" || \
              curl -fsS "http://127.0.0.1:${UVICORN_PORT}/livez" || \
              curl -fsS "http://127.0.0.1:${UVICORN_PORT}/" || exit 1'

# Default entrypoint: gunicorn with uvicorn workers
# Detect common app module paths: backend.app.main:app | app.main:app | main:app
# You can override MODULE_PATH via docker run -e MODULE_PATH=...
ENV MODULE_PATH="backend.app.main:app,app.main:app,main:app"

# Small launcher that selects the first existing module
CMD ["/bin/sh", "-c", "\
set -e; \
IFS=',' read -r -a CANDIDATES <<<\"$MODULE_PATH\"; \
APP_MODULE=\"\"; \
for m in \"${CANDIDATES[@]}\"; do \
  python -c \"import importlib; import sys; sys.exit(0) if (lambda x: importlib.import_module(x.split(':')[0]))('$m') else sys.exit(1)\" 2>/dev/null && { APP_MODULE=\"$m\"; break; }; \
done; \
if [ -z \"$APP_MODULE\" ]; then \
  echo \"No viable app module found in MODULE_PATH='$MODULE_PATH'.\" >&2; \
  exit 1; \
fi; \
exec gunicorn \"$APP_MODULE\" \
  --worker-class=\"$GUNICORN_WORKER_CLASS\" \
  --workers=\"${UVICORN_WORKERS}\" \
  --bind=\"${UVICORN_HOST}:${UVICORN_PORT}\" \
  --timeout=\"${GUNICORN_TIMEOUT}\" \
  --keep-alive=\"${GUNICORN_KEEPALIVE}\" \
  --log-level=\"info\" \
  --access-logfile=\"-\" \
  --error-logfile=\"-\"\
"]
