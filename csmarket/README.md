# README
# CSMarket

CSMarket это Telegram-first маркетплейс для листинга и безопасного обмена CS2 скинами с вшитыми механизмами эскроу, событиями в реальном времени, платежами, аудитом и модульной архитектурой сервисов.

Документ не содержит утверждений, требующих внешней проверки, кроме ссылок на официальную документацию в разделе References.

## Цели и принципы

- Telegram Mini App как основной UI.
- Telegram Bot как канал входа, уведомлений, платежных сообщений и поддержки.
- Реальное время для статусов сделок и уведомлений.
- Надежность через outbox и асинхронные обработчики событий.
- Безопасность через валидацию Telegram initData на сервере и контроль доверия к данным.
- Расширяемость через отдельные сервисы домена: market, steam, pricing, wallet, ledger, risk, ai.

## Репозиторий

- services/gateway-api
  HTTP API, realtime (WS, SSE), вебхуки, auth, оркестрация use-cases, read модели, административные операции.
- services/market-core
  Домен сделок: листинги, ордера, эскроу, диспуты, комиссии, ограничения.
- services/steam-core
  Интеграция Steam: инвентарь, нормализация предметов, сопровождение трейд-офферов, валидация сущностей.
- services/pricing-core
  Фиды цен, агрегатор, кэш, контроль аномалий.
- services/wallet-core
  Платежи, статусы транзакций, депозиты и выводы, webhooks провайдеров.
- services/ledger-core
  Учет балансов и комиссий (ledger), reconciliation, идемпотентность финансовых операций.
- services/risk-core
  Антифрод правила, сигналы, скоринг, лимиты, санкционные списки (минимальный комплаенс).
- services/events-worker
  Доставка outbox событий, ретраи, уведомления в бота, плановые джобы (обновление цен, сверки).
- services/ai-core
  Надстройка: поддержка, модерация контента, семантический поиск, антифрод скоринг как вспомогательный сигнал.

- telegram_bot
  aiogram бот: /start, открыть mini app, уведомления, поддержка, платежные сценарии.
- miniapp_frontend
  React TypeScript mini app: каталог, листинги, покупка, продажа, статусы сделок, кошелек, PRO, support chat.
- admin_frontend
  Минимальная админка: диспуты, листинги, модерация, пользователи, лимиты, платежные сверки.
- platform
  Общие библиотеки: config, logging, observability, security primitives, idempotency, outbox, http clients.
- shared
  Контракты DTO и событий, версии контрактов, общие типы для Python и Web.

## Доменная модель на уровне терминов

- Listing
  Публичное предложение продать предмет по фиксированной цене.
- Order
  Запрос купить по цене или условиям.
- Deal
  Состояние сделки между сторонами.
- Escrow
  Условия удержания средств до выполнения действий по передаче предмета.
- Dispute
  Спорная ситуация с эскалацией и решением администратором.
- Outbox event
  Событие, записанное транзакционно рядом с доменной операцией для надежной доставки в очередь и downstream.

## Быстрый старт

Требования
- Docker Desktop
- Node.js и pnpm для фронтендов
- Python 3.12 для локальной разработки сервисов без контейнеров

Команды
- docker compose up -d
- docker compose logs -f gateway-api
- pnpm install и pnpm dev в miniapp_frontend
- pnpm install и pnpm dev в admin_frontend

Сервисы в dev окружении
- gateway-api: http://localhost:8000
- miniapp_frontend: http://localhost:5173
- admin_frontend: http://localhost:5174
- grafana: http://localhost:3000
- prometheus: http://localhost:9090
- minio: http://localhost:9001

Порты и хосты зависят от docker-compose.yml.

## Переменные окружения

В корне репозитория используется .env для docker compose. Пример лежит в .env.example.

Группы переменных
- Telegram
  TELEGRAM_BOT_TOKEN
  TELEGRAM_WEBAPP_URL
  TELEGRAM_PROVIDER_TOKEN если используется классический payments provider
- Database
  POSTGRES_DSN или POSTGRES_HOST, POSTGRES_PORT, POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD
- Redis
  REDIS_DSN
- Broker
  RABBITMQ_DSN
- Storage
  MINIO_ENDPOINT, MINIO_ACCESS_KEY, MINIO_SECRET_KEY, MINIO_BUCKET
- Security
  APP_SECRET_KEY, JWT_SECRET если включен JWT, CORS_ORIGINS
- Observability
  OTEL_EXPORTER_OTLP_ENDPOINT, LOG_LEVEL
- Feature flags
  FEATURES_PRO, FEATURES_WITHDRAWALS, FEATURES_STEAM_TRADES

## Безопасность

Telegram Mini Apps
- Данные из initDataUnsafe на клиенте не считаются доверенными.
- На сервере используется строка initData после валидации подписи и времени жизни.
- Запрещено принимать решения о доступах, лимитах и деньгах по данным, не прошедшим серверную валидацию.

Идемпотентность и конкуренция
- В gateway-api используется Idempotency-Key для критических операций (создание сделки, депозит, вывод).
- Финансовые операции проводят запись в ledger с детерминированным ключом операции.

События
- Outbox фиксируется в одной транзакции с доменной записью.
- events-worker отвечает за доставку событий в очередь и повторные попытки.

Доступы
- Админские функции изолированы, должны требовать отдельной роли и отдельного токена доступа.

## Реальное время

- WS для интерактивных статусов и пушей по сделкам.
- SSE для простого потокового обновления и совместимости при ограничениях прокси.
- Протокол сообщений документируется в docs/realtime-events.md.

## Платежи и монетизация

- Подписка PRO включает расширенные лимиты, приоритет поддержки, доступ к расширенной аналитике.
- wallet-core отвечает за провайдеров криптоплатежей и статусы.
- Telegram payments могут использоваться для отдельных сценариев, если это нужно продуктово.

Модель комиссий и удержаний
- Правила комиссий живут в market-core policies.
- Учет комиссий и удержаний делается через ledger-core.

## Тестирование

Уровни
- Unit тесты в сервисах
- Integration тесты в tests/integration с поднятым docker compose
- Contract тесты на схемы событий и DTO
- E2E сценарии для miniapp и admin через playwright
- Load тесты через k6 для realtime и ключевых API

Команды
- scripts/test.ps1
- scripts/e2e.ps1

## Observability

- Логи структурированные, с request_id и correlation_id.
- Метрики Prometheus для API, воркеров и бота.
- Трейсинг через OpenTelemetry при наличии экспортера.

## Документация

- docs/architecture.md общая архитектура
- docs/domain-model.md доменная модель
- docs/security.md модель угроз и контрмеры
- docs/payments.md платежные сценарии
- docs/steam-integration.md границы интеграции Steam
- docs/realtime-events.md протокол событий и realtime

## References

Официальная документация Telegram Mini Apps по Web Apps и требованию валидировать initData на сервере
- https://core.telegram.org/bots/webapps

Описание валидации init data и HMAC подхода в документации Telegram Mini Apps
- https://docs.telegram-mini-apps.com/platform/init-data

Telegram Bot Payments API
- https://core.telegram.org/bots/payments

Telegram Payments for digital goods and services
- https://core.telegram.org/bots/payments-stars

FastAPI WebSockets documentation
- https://fastapi.tiangolo.com/advanced/websockets/

aiogram sendInvoice documentation
- https://docs.aiogram.dev/en/v3.20.0/api/methods/send_invoice.html

pgvector repository
- https://github.com/pgvector/pgvector

Neon pgvector documentation
- https://neon.com/docs/extensions/pgvector
