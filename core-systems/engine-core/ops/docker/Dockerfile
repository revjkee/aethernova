# ========================================================================
# Industrial-grade Dockerfile for engine-core
# Location: engine-core/ops/docker/Dockerfile
# ========================================================================

# === Builder Stage (isolated, reproducible build)
FROM python:3.11-slim AS builder

ENV POETRY_VERSION=1.8.2
ENV VENV_PATH="/opt/venv"

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl build-essential gcc libpq-dev git \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN curl -sSL https://install.python-poetry.org | python3 - \
    && ln -s /root/.local/bin/poetry /usr/local/bin/poetry

WORKDIR /app

# Copy only required files for dependency resolution
COPY pyproject.toml poetry.lock ./

# Install deps in virtualenv to avoid polluting system site-packages
RUN poetry config virtualenvs.in-project true \
    && poetry install --no-dev --no-interaction --no-ansi

# Copy full source (after deps to maximize cache efficiency)
COPY ./src ./src

# === Runtime Stage (minimal secure image)
FROM python:3.11-slim AS runtime

ENV VENV_PATH="/opt/venv"
ENV PATH="$VENV_PATH/bin:$PATH"

# Install runtime deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 curl tini \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy virtualenv from builder
COPY --from=builder /app/.venv $VENV_PATH

# Copy app source
COPY --from=builder /app/src /app/src

# Set working directory
WORKDIR /app

# Create non-root user
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

# Set permissions and switch user
RUN chown -R appuser:appgroup /app
USER appuser

# SBOM optional layer (Syft)
LABEL org.opencontainers.image.source="https://github.com/YOUR_REPO/engine-core"
LABEL org.opencontainers.image.description="engine-core container with poetry runtime"

ENTRYPOINT ["tini", "--"]
CMD ["python", "-m", "engine_core.app"]

