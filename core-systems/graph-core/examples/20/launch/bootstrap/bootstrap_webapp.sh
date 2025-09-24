#!/bin/bash

set -e

echo "[WEBAPP] Запуск интерфейса TeslaAI Genesis..."

# Проверка необходимых переменных окружения
: "${WEBAPP_PORT:?WEBAPP_PORT не установлен}"
: "${NODE_ENV:=production}"
: "${VITE_API_BASE_URL:?VITE_API_BASE_URL не установлен}"
: "${VITE_WEBAPP_PUBLIC_KEY:?VITE_WEBAPP_PUBLIC_KEY не установлен}"

# Каталог фронтенда
WEBAPP_DIR="/opt/teslaai/frontend"

# Генерация runtime конфигурации (если нужно)
RUNTIME_ENV="$WEBAPP_DIR/.env"
echo "[WEBAPP] Генерация runtime .env в $RUNTIME_ENV"
cat <<EOF > "$RUNTIME_ENV"
VITE_API_BASE_URL=$VITE_API_BASE_URL
VITE_WEBAPP_PUBLIC_KEY=$VITE_WEBAPP_PUBLIC_KEY
NODE_ENV=$NODE_ENV
EOF

# Установка зависимостей (однократно)
if [ ! -d "$WEBAPP_DIR/node_modules" ]; then
    echo "[WEBAPP] Установка зависимостей..."
    cd "$WEBAPP_DIR"
    npm ci
fi

# Сборка проекта (если не собран)
if [ ! -d "$WEBAPP_DIR/dist" ]; then
    echo "[WEBAPP] Сборка WebApp..."
    cd "$WEBAPP_DIR"
    npm run build
fi

# Запуск dev-сервера или production-сервера
if [[ "$NODE_ENV" == "development" ]]; then
    echo "[WEBAPP] Запуск dev-сервера на $WEBAPP_PORT"
    cd "$WEBAPP_DIR"
    npx vite --port "$WEBAPP_PORT"
else
    echo "[WEBAPP] Запуск production-сервера..."
    npx serve "$WEBAPP_DIR/dist" --listen "$WEBAPP_PORT"
fi
