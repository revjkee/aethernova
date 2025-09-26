# syntax=docker/dockerfile:1.8

############################################
# 1) Builder: сборка фронтенда (Vite/React)
############################################
FROM node:22-alpine AS builder

# Безопасные и воспроизводимые окружения
ENV NODE_ENV=production \
    CI=true \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_AUDIT=false \
    # Увеличиваем память для больших бандлов, если нужно
    NODE_OPTIONS=--max_old_space_size=4096

WORKDIR /app

# Часто нужные системные зависимости для сборки нативных модулей (опционально)
# Ставим их как виртуальный пакет и удалим в конце стадии
RUN apk add --no-cache --virtual .build-deps python3 make g++ git

# Оптимизация кэша: копируем только манифесты зависимостей
# Поддержка npm / yarn / pnpm — определяется по lock-файлу
COPY package.json ./
COPY package-lock.json* ./
COPY npm-shrinkwrap.json* ./
COPY yarn.lock* ./
COPY pnpm-lock.yaml* ./

# Включаем corepack для yarn/pnpm при необходимости
RUN corepack enable || true

# Устанавливаем зависимости с использованием кэша менеджера пакетов
# - npm: кэшируем /root/.npm
# - yarn: кэшируем /usr/local/share/.cache/yarn
# - pnpm: кэшируем /root/.local/share/pnpm/store
RUN --mount=type=cache,target=/root/.npm \
    --mount=type=cache,target=/usr/local/share/.cache/yarn \
    --mount=type=cache,target=/root/.local/share/pnpm/store \
    set -eux; \
    if [ -f pnpm-lock.yaml ]; then \
        corepack prepare pnpm@latest --activate; \
        pnpm install --frozen-lockfile; \
    elif [ -f yarn.lock ]; then \
        corepack prepare yarn@stable --activate; \
        yarn install --frozen-lockfile; \
    elif [ -f package-lock.json ] || [ -f npm-shrinkwrap.json ]; then \
        npm ci; \
    else \
        npm install; \
    fi

# Копируем остальной исходный код
COPY . .

# Сборка проекта
# Используем npm run build (подходит и после yarn/pnpm install — скрипты читаются из package.json)
RUN --mount=type=cache,target=/root/.npm \
    --mount=type=cache,target=/usr/local/share/.cache/yarn \
    --mount=type=cache,target=/root/.local/share/pnpm/store \
    set -eux; \
    npm run build

# Убираем сборочные зависимости (только для этой стадии)
RUN apk del .build-deps || true

############################################
# 2) Runtime: лёгкий и безопасный Nginx
############################################
FROM nginx:1.27-alpine AS runtime

# Метаданные образа (OCI)
LABEL org.opencontainers.image.title="Frontend (SPA) - Production Image" \
      org.opencontainers.image.description="Optimized multi-stage build for Vite/React SPA with Nginx, gzip, caching and SPA fallback." \
      org.opencontainers.image.vendor="Aethernova / NeuroCity" \
      org.opencontainers.image.source="https://example.com/repo" \
      org.opencontainers.image.licenses="Apache-2.0"

# Рабочая директория nginx и права
WORKDIR /usr/share/nginx/html

# Чистим дефолтный конфиг и добавляем свой
RUN rm -f /etc/nginx/conf.d/default.conf

# Конфигурация Nginx:
# - слушает 8080 (не root-порт)
# - gzip для текстовых ресурсов
# - агрессивное кэширование хэшированных ассетов (например, /assets/*)
# - no-cache для index.html
# - SPA fallback: try_files ... /index.html
# - базовые security headers (без жёсткого CSP, чтобы не ломать приложение)
RUN <<'NGINX_CONF' cat >/etc/nginx/conf.d/spa.conf
server {
    listen 8080;
    server_name _;

    root   /usr/share/nginx/html;
    index  index.html;

    # Gzip сжатие
    gzip on;
    gzip_types text/plain text/css application/javascript application/json application/xml \
               application/rss+xml text/xml image/svg+xml application/vnd.ms-fontobject \
               application/x-font-ttf font/opentype application/wasm;
    gzip_min_length 1024;
    gzip_comp_level 5;

    # Безопасные заголовки (базовый набор)
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

    # Кэширование: хэшированные ассеты (например, /assets/*) на год
    location ~* ^/assets/ {
        access_log off;
        expires 1y;
        add_header Cache-Control "public, immutable";
        try_files $uri =404;
    }

    # Статика остальных типов (картинки, иконки, шрифты) — 7 дней
    location ~* \.(png|jpe?g|gif|ico|svg|webp|avif|ttf|otf|woff2?)$ {
        access_log off;
        expires 7d;
        add_header Cache-Control "public";
        try_files $uri =404;
    }

    # Главная SPA-страница: без кэширования
    location = /index.html {
        expires -1;
        add_header Cache-Control "no-store";
        try_files $uri =404;
    }

    # Основной роутинг SPA
    location / {
        try_files $uri $uri/ /index.html;
    }

    # Здоровье сервиса
    location /healthz {
        access_log off;
        default_type text/plain;
        return 200 "ok\n";
    }
}
NGINX_CONF

# Копируем собранную статику из builder
COPY --from=builder /app/dist/ /usr/share/nginx/html/

# Права для небезопасного root не нужны: используем пользователя nginx и порт 8080
RUN chown -R nginx:nginx /usr/share/nginx/html
USER nginx

EXPOSE 8080

# Healthcheck контейнера (простая проверка)
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1

# Запуск Nginx в foreground
CMD ["nginx", "-g", "daemon off;"]
