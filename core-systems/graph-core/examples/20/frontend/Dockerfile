# Используем официальный Node.js образ для сборки
FROM node:18-alpine AS build

WORKDIR /app

# Копируем package.json и package-lock.json (если есть)
COPY package*.json ./

# Устанавливаем зависимости
RUN npm install

# Копируем весь исходный код
COPY . .

# Собираем React-приложение для продакшена
RUN npm run build

# Используем легковесный Nginx для сервировки статичных файлов
FROM nginx:stable-alpine

# Копируем собранные файлы из стадии build в директорию Nginx
COPY --from=build /app/build /usr/share/nginx/html

# Копируем конфигурацию Nginx, если нужно (опционально)
# COPY nginx.conf /etc/nginx/nginx.conf

# Открываем порт 3000 (или 80, если не менял в nginx)
EXPOSE 80

# Запускаем Nginx
CMD ["nginx", "-g", "daemon off;"]
