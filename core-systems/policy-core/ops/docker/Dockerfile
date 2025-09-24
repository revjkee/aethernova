# policy-core/ops/docker/Dockerfile
# Industrial, multi-stage Dockerfile for Policy-as-Code (OPA/Rego)

# =========================
# Stage 1: Fetch & verify OPA
# =========================
FROM alpine:3.20 AS builder-opa
ARG OPA_VERSION=0.66.0
# Optional checksum for strict verification (linux-amd64)
ARG OPA_SHA256=""
RUN apk add --no-cache curl ca-certificates tar coreutils \
 && update-ca-certificates

WORKDIR /tmp/opa
RUN curl -fsSL -o opa https://openpolicyagent.org/downloads/v${OPA_VERSION}/opa_linux_amd64_static \
 && chmod +x ./opa \
 && if [ -n "${OPA_SHA256}" ]; then \
        echo "${OPA_SHA256}  opa" | sha256sum -c - ; \
    else \
        echo "WARN: OPA_SHA256 is empty; checksum verification is skipped." ; \
    fi

# =========================
# Stage 2: Build policy bundle
# =========================
FROM alpine:3.20 AS builder-bundle
ARG POLICIES_DIR=policies
COPY --from=builder-opa /tmp/opa/opa /usr/local/bin/opa
RUN apk add --no-cache ca-certificates \
 && update-ca-certificates

# Copy policies and (optionally) tests into build context
WORKDIR /src
# Expect build context at repo root: policies/ and tests/ are optional
COPY ${POLICIES_DIR}/ /src/policies/
# If you keep OPA unit tests for policies under tests/, they will be used automatically
COPY tests/ /src/tests/ 2>/dev/null || true

# Fail-fast: fmt diff must be empty (enforces formatting)
RUN /usr/local/bin/opa fmt -d /src/policies

# Run OPA policy tests (if present)
RUN if [ -d "/src/tests" ]; then /usr/local/bin/opa test /src/policies /src/tests -v; else echo "No OPA tests detected, continuing"; fi

# Build OPA bundle (tar.gz)
RUN mkdir -p /out \
 && /usr/local/bin/opa build -b /src/policies -o /out/bundle.tar.gz

# =========================
# Stage 3a: Runtime (Distroless, production)
# =========================
FROM gcr.io/distroless/base:nonroot AS runtime-distroless
# OCI labels
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
ARG VERSION=0.0.0
LABEL org.opencontainers.image.title="policy-core (OPA runtime)" \
      org.opencontainers.image.description="Hardened OPA runtime with embedded policy bundle" \
      org.opencontainers.image.source="https://example.org/repo" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0"

# Non-root user is pre-defined in distroless (uid 65532)
USER 65532:65532
WORKDIR /app

# Copy OPA binary and bundle
COPY --from=builder-opa     /tmp/opa/opa        /usr/bin/opa
COPY --from=builder-bundle  /out/bundle.tar.gz  /app/bundle.tar.gz

# Expose OPA HTTP API
EXPOSE 8181

# Secure defaults:
# - server mode
# - listen on 0.0.0.0:8181
# - load local bundle
# - enable console decision logs
ENTRYPOINT ["/usr/bin/opa","run","--server","--addr=0.0.0.0:8181","-b","/app/bundle.tar.gz","--set","decision_logs.console=true"]

# =========================
# Stage 3b: Runtime (Alpine, diagnostics)
# build with: --target runtime-alpine
# =========================
FROM alpine:3.20 AS runtime-alpine
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
ARG VERSION=0.0.0
LABEL org.opencontainers.image.title="policy-core (OPA runtime, alpine)" \
      org.opencontainers.image.description="OPA runtime with diagnostics tooling (curl, healthcheck)" \
      org.opencontainers.image.source="https://example.org/repo" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN addgroup -S app && adduser -S -G app -u 65532 app \
 && apk add --no-cache ca-certificates curl \
 && update-ca-certificates

USER 65532:65532
WORKDIR /app

COPY --from=builder-opa     /tmp/opa/opa        /usr/local/bin/opa
COPY --from=builder-bundle  /out/bundle.tar.gz  /app/bundle.tar.gz

EXPOSE 8181

HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD \
    curl -fsS http://127.0.0.1:8181/health || exit 1

ENTRYPOINT ["/usr/local/bin/opa","run","--server","--addr=0.0.0.0:8181","-b","/app/bundle.tar.gz","--set","decision_logs.console=true"]
