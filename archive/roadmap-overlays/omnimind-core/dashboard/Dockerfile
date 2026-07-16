# syntax=docker/dockerfile:1
###############################################################################
# Builder stage: reproducible build, dependency caching, asset precompression
###############################################################################
FROM node:20-bullseye-slim AS builder

ARG APP_DIR=/app
ARG NODE_ENV=production
ENV NODE_ENV=${NODE_ENV}
WORKDIR ${APP_DIR}

# Create non-root user to run build (safer in some CI contexts)
RUN groupadd -r app && useradd -r -g app -m app

# Install build-time tools for precompression
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates gzip brotli \
 && rm -rf /var/lib/apt/lists/*

# Copy package manifests first to leverage Docker cache for dependencies
# (supports npm/yarn/pnpm; adapt if using pnpm)
COPY package*.json ./
# If using pnpm: copy pnpm-lock.yaml and install pnpm
RUN --mount=type=cache,target=/root/.npm \
    npm ci --no-audit --prefer-offline

# Copy app sources
COPY . .

# Ensure build script exists; fail early if not
RUN if ! grep -q "build" package.json; then echo "package.json must contain a build script"; exit 1; fi

# Build (expects output in ./dist or ./build — adjust below if needed)
RUN npm run build

# Detect output dir (dist preferred, fallback to build)
RUN if [ -d "dist" ]; then echo "DIST=dist" > /tmp/output_dir; \
    elif [ -d "build" ]; then echo "DIST=build" > /tmp/output_dir; \
    else echo "No build output found (dist/ or build/)"; exit 1; fi

# Pre-compress static assets with gzip (create .gz alongside originals)
# Use aggressive compression for text assets; keep originals for safety
RUN set -eux; \
    . /tmp/output_dir; \
    find ${DIST} -type f -regextype posix-extended \
      -regex '.*\.(js|css|html|svg|json|txt|wasm|map|xml|ico)$' -print0 \
      | xargs -0 -n1 -P4 gzip -9 -k -f

# Optional: generate a lightweight checksum file for integrity checks in CI
RUN . /tmp/output_dir; \
    cd ${DIST} && find . -type f -print0 | xargs -0 sha256sum > /sha256sums.txt

###############################################################################
# Production stage: nginx serves static files, supports gzip_static
###############################################################################
FROM nginx:stable-alpine AS production

ARG APP_DIR=/app
ARG NGX_PORT=8080
ENV PORT=${NGX_PORT}
EXPOSE ${NGX_PORT}

LABEL org.opencontainers.image.title="omnimind-core-dashboard" \
      org.opencontainers.image.description="Industrial production image for omnimind SPA" \
      org.opencontainers.image.vendor="Aethernova / Omnimind"

# Install runtime tools for env substitution if needed
RUN apk add --no-cache gettext

# Security: reduce default nginx logging noise and run as non-privileged port 8080
# We'll write a production nginx config below.
# Copy built assets from builder
COPY --from=builder /tmp/output_dir /tmp/output_dir || true
# Determine and copy actual dist/build folder
# (The builder left a file /tmp/output_dir containing "DIST=dist" or "DIST=build")
COPY --from=builder /app/dist /usr/share/nginx/html 2>/dev/null || true
COPY --from=builder /app/build /usr/share/nginx/html 2>/dev/null || true

# Add a robust nginx configuration (serves precompressed .gz when available, SPA fallback,
# strict caching for fingerprinted assets, short caching for index.html).
RUN rm /etc/nginx/conf.d/default.conf
RUN cat > /etc/nginx/nginx.conf <<'NGINX_CONF'
user  nginx;
worker_processes  auto;
error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;

events {
  worker_connections 1024;
}

http {
  include       /etc/nginx/mime.types;
  default_type  application/octet-stream;

  sendfile        on;
  tcp_nopush      on;
  tcp_nodelay     on;
  keepalive_timeout 65;
  types_hash_max_size 2048;

  # Gzip for dynamic responses (nginx can also serve .gz via gzip_static on)
  gzip on;
  gzip_min_length 1024;
  gzip_proxied any;
  gzip_comp_level 6;
  gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

  # Server
  server {
    listen       8080;
    server_name  localhost;
    root   /usr/share/nginx/html;
    index  index.html;

    # Security headers (minimal set)
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options SAMEORIGIN;
    add_header Referrer-Policy no-referrer-when-downgrade;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Try compressed (.gz) then normal file; fallback to index.html for SPA routing
    location / {
      # Try exact uri, then try uri.gz (gzip_static), then /index.html
      try_files $uri $uri.gz $uri/ /index.html;
    }

    # Serve fingerprinted assets with long cache
    location ~* \.(?:manifest|appcache|html|xml|json)$ {
      try_files $uri $uri.gz =404;
      add_header Cache-Control "no-cache, must-revalidate";
    }

    location ~* \.(?:css|js|woff2?|ttf|otf|eot|ico|png|jpe?g|gif|svg|webp)$ {
      try_files $uri $uri.gz =404;
      add_header Cache-Control "public, max-age=31536000, immutable";
      access_log off;
      expires 365d;
    }

    # Serve source maps with no-cache (if present)
    location ~* \.map$ {
      try_files $uri =404;
      add_header Cache-Control "no-cache";
    }

    # Health endpoint (simple)
    location = /health {
      add_header Content-Type text/plain;
      return 200 'ok';
    }

    # Deny access to hidden files
    location ~ /\. {
      deny all;
      access_log off;
      log_not_found off;
    }
  }
}
NGINX_CONF

# Entrypoint script: optional runtime env substitution for env.js.template -> env.js
RUN cat > /docker-entrypoint.sh <<'ENTRY' \
 && chmod +x /docker-entrypoint.sh
#!/bin/sh
set -e

# If there's an env template for runtime configuration, substitute variables
TEMPLATE="/usr/share/nginx/html/env.js.template"
TARGET="/usr/share/nginx/html/env.js"

if [ -f "\$TEMPLATE" ]; then
  echo "Found env template, substituting environment variables..."
  # export all env variables for envsubst
  envsubst '\$API_URL \$NODE_ENV \$OTHER_RUNTIME_VAR' < "\$TEMPLATE" > "\$TARGET" || :
fi

# If /health request should be available, ensure nginx listens on PORT
sed -i "s/listen 8080;/listen ${PORT};/g" /etc/nginx/nginx.conf || true

exec nginx -g 'daemon off;'
ENTRY

# Ensure non-root ownership where possible
RUN chown -R nginx:nginx /usr/share/nginx/html || true

# Healthcheck (container runtime will check /health)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:${NGX_PORT}/health || exit 1

ENTRYPOINT ["/docker-entrypoint.sh"]
