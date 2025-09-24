# frontend.Dockerfile
# Сборка и запуск фронтенда на Vite + React + TypeScript
# Используется двухступенчатая сборка для уменьшения размера итогового образа

# Этап 1: сборка
FROM node:20-alpine AS build

WORKDIR /app

# Копируем файлы зависимостей
COPY frontend/package.json frontend/package-lock.json* frontend/yarn.lock* ./

# Устанавливаем зависимости (предпочтительно yarn или npm)
RUN if [ -f yarn.lock ]; then yarn install --frozen-lockfile; else npm ci; fi

# Копируем весь исходный код фронтенда
COPY frontend/ ./

# Сборка проекта для продакшена
RUN npm run build

# Этап 2: запуск nginx с собранным фронтендом
FROM nginx:stable-alpine

# Удаляем стандартный контент nginx
RUN rm -rf /usr/share/nginx/html/*

# Копируем собранный фронтенд из этапа сборки
COPY --from=build /app/dist /usr/share/nginx/html

# Копируем кастомный конфиг nginx (если есть)
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf

# Открываем порт 80
EXPOSE 80

# Запускаем nginx в фореграунд режиме
CMD ["nginx", "-g", "daemon off;"]
