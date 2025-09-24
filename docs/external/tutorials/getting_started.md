# Вводное руководство (Getting Started)

## Введение

Это руководство поможет новым пользователям быстро и эффективно начать работу с нашим проектом TeslaAI Genesis. Вы получите четкие инструкции по установке, настройке и базовому использованию ключевых компонентов системы.

---

## 1. Требования к системе

- Операционная система: Linux (Ubuntu 20.04+ рекомендуется), macOS, Windows 10+ с WSL2.
- Python 3.10+
- Docker и Docker Compose (для контейнеризации сервисов)
- Git
- Доступ к интернету для загрузки зависимостей

---

## 2. Клонирование репозитория

```bash
git clone https://github.com/your_org/teslaai-genesis.git
cd teslaai-genesis

3. Установка зависимостей

Используйте виртуальное окружение Python:

python3 -m venv venv
source venv/bin/activate   # Linux/macOS
venv\Scripts\activate      # Windows
pip install --upgrade pip
pip install -r requirements.txt

4. Настройка окружения

Создайте файл .env в корне проекта на основе .env.example и заполните необходимые переменные:

API_KEY=ваш_ключ_для_внешних_сервисов
DATABASE_URL=postgresql://user:password@localhost/dbname
...

5. Запуск сервисов

Для локального запуска используйте Docker Compose:

docker-compose up --build

Либо запускайте компоненты по отдельности через скрипты в папке /scripts.
6. Проверка установки

    Перейдите по адресу http://localhost:8000 для проверки доступности API.

    Запустите тесты:

pytest tests/

7. Основные команды и скрипты
Команда	Описание
scripts/setup_env.sh	Настройка переменных окружения
scripts/security_scan.sh	Запуск проверки безопасности
scripts/deploy.sh	Общий скрипт деплоя
scripts/test_runner.sh	Запуск тестов
8. Полезные ссылки и документация

    Официальный сайт проекта: https://teslaai.genesis

    Документация API: http://localhost:8000/docs (при локальном запуске)

    Канал поддержки в Telegram: @TeslaAIGenesisSupport

9. Контакты и поддержка

Для вопросов и помощи обращайтесь:

    Email: support@teslaai.genesis

    Telegram: @TeslaAIGenesisSupport

Автор: Команда TeslaAI Genesis
Дата: 2025-07-14
Версия: 1.0


Файл готов к публикации как официальный стартовый материал для новых участнико