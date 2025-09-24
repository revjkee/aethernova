Руководство по развертыванию проекта Telegram Mini App
1. Введение
Данный документ описывает процесс развертывания и настройки проекта, включающего три ключевых компонента:

FastAPI backend

Telegram бот (aiogram)

Фоновый воркер для асинхронных задач

Все компоненты разделены для масштабируемости и удобства поддержки.

2. Предварительные требования
Сервер или VPS с Linux (рекомендуется Ubuntu 22.04+)

Python 3.13+

PostgreSQL (рекомендуемая версия 14+)

Redis (рекомендуемая версия 6+)

Доступ в интернет для получения обновлений и зависимостей

Телеграм токен для бота

Утилиты: git, curl, nano/vim, systemctl (для настройки сервисов)

3. Подготовка окружения
3.1 Установка Python и создание виртуального окружения
bash
Копировать
Редактировать
sudo apt update && sudo apt upgrade -y
sudo apt install python3.13 python3.13-venv python3-pip -y
python3.13 -m venv /opt/tgminiapp/venv
source /opt/tgminiapp/venv/bin/activate
pip install --upgrade pip
3.2 Установка PostgreSQL и Redis
bash
Копировать
Редактировать
sudo apt install postgresql postgresql-contrib redis-server -y
sudo systemctl enable postgresql redis-server
sudo systemctl start postgresql redis-server
3.3 Создание базы данных и пользователя PostgreSQL
bash
Копировать
Редактировать
sudo -u postgres psql
CREATE DATABASE tgminiapp_db;
CREATE USER tgminiapp_user WITH PASSWORD 'strong_password_here';
ALTER ROLE tgminiapp_user SET client_encoding TO 'utf8';
ALTER ROLE tgminiapp_user SET default_transaction_isolation TO 'read committed';
ALTER ROLE tgminiapp_user SET timezone TO 'UTC';
GRANT ALL PRIVILEGES ON DATABASE tgminiapp_db TO tgminiapp_user;
\q
4. Настройка проекта
4.1 Клонирование репозитория и установка зависимостей
bash
Копировать
Редактировать
git clone https://your-repo-url.git /opt/tgminiapp
cd /opt/tgminiapp
source /opt/tgminiapp/venv/bin/activate
pip install -r requirements.txt
4.2 Создание файла окружения .env
Пример .env файла:

ini
Копировать
Редактировать
TELEGRAM_TOKEN=your_telegram_bot_token
DATABASE_URL=postgres://tgminiapp_user:strong_password_here@localhost:5432/tgminiapp_db
REDIS_URL=redis://localhost:6379/0
API_HOST=0.0.0.0
API_PORT=8000
DEBUG=False
5. Применение миграций
bash
Копировать
Редактировать
aerich upgrade
Или с Alembic:

bash
Копировать
Редактировать
alembic upgrade head
6. Запуск компонентов
6.1 Запуск FastAPI backend
bash
Копировать
Редактировать
python entrypoints/run_api.py
6.2 Запуск Telegram бота
bash
Копировать
Редактировать
python entrypoints/run_bot.py
6.3 Запуск фонового воркера
bash
Копировать
Редактировать
python entrypoints/run_worker.py
7. Настройка автозапуска (systemd)
Создайте systemd юниты для каждого сервиса:

7.1 Backend (fastapi.service)
ini
Копировать
Редактировать
[Unit]
Description=FastAPI backend for Telegram Mini App
After=network.target

[Service]
User=youruser
WorkingDirectory=/opt/tgminiapp
ExecStart=/opt/tgminiapp/venv/bin/python /opt/tgminiapp/entrypoints/run_api.py
Restart=always
EnvironmentFile=/opt/tgminiapp/.env

[Install]
WantedBy=multi-user.target
7.2 Telegram бот (bot.service)
ini
Копировать
Редактировать
[Unit]
Description=Telegram Bot service
After=network.target redis.service postgresql.service

[Service]
User=youruser
WorkingDirectory=/opt/tgminiapp
ExecStart=/opt/tgminiapp/venv/bin/python /opt/tgminiapp/entrypoints/run_bot.py
Restart=always
EnvironmentFile=/opt/tgminiapp/.env

[Install]
WantedBy=multi-user.target
7.3 Воркер (worker.service)
ini
Копировать
Редактировать
[Unit]
Description=Background Worker for Telegram Mini App
After=network.target redis.service postgresql.service

[Service]
User=youruser
WorkingDirectory=/opt/tgminiapp
ExecStart=/opt/tgminiapp/venv/bin/python /opt/tgminiapp/entrypoints/run_worker.py
Restart=always
EnvironmentFile=/opt/tgminiapp/.env

[Install]
WantedBy=multi-user.target
8. Управление сервисами
bash
Копировать
Редактировать
sudo systemctl daemon-reload
sudo systemctl enable fastapi.service bot.service worker.service
sudo systemctl start fastapi.service bot.service worker.service

sudo systemctl status fastapi.service
sudo journalctl -u bot.service -f
9. Резервное копирование
Регулярно делайте дампы базы PostgreSQL.

Резервируйте Redis данные (например, snapshot).

Копируйте .env и важные конфиги.

10. Мониторинг и логирование
Используйте journalctl для просмотра логов systemd.

В дальнейшем рекомендуется подключить Prometheus/Grafana для мониторинга.

Рассмотрите интеграцию Sentry для отслеживания ошибок.

Итог
Этот гайд покрывает весь необходимый минимум для качественного и стабильного развёртывания Telegram Mini App.
Разделение компонентов позволит масштабировать проект и поддерживать его легко.

