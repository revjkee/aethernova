# api
# CSMarket API

Версия документа: 1.0
Статус: Contract-first (этот документ является контрактом и источником правды для интеграций)

## 1. Область и принципы

Этот документ описывает внешний HTTP API сервиса CSMarket. Он предназначен для:
- Frontend (Web, Telegram Mini App)
- Внутренних сервисов (orchestrator, payments, inventory)
- QA и нагрузочного тестирования

В документе нет утверждений о внешних системах или комиссиях Steam. Если такие сведения нужны, они должны быть подтверждены отдельными источниками. Не могу подтвердить это.

## 2. Базовые параметры

Base URL:
- Production: https://api.csmarket.example
- Staging: https://staging-api.csmarket.example

API Prefix:
- /api/v1

Content-Type:
- application/json; charset=utf-8

Часовой пояс дат:
- Все даты и времена в ISO 8601 UTC, пример: 2026-02-13T12:34:56Z

Версионирование:
- Major версия в пути: /api/v1
- Minor изменения без ломания контракта в рамках v1 допускаются

## 3. Безопасность

### 3.1 TLS
- Только HTTPS. HTTP запрещён.

### 3.2 Аутентификация
Поддерживаются два механизма:
1) Bearer JWT
- Заголовок: Authorization: Bearer <token>

2) API Key для server-to-server (если включено в конкретной среде)
- Заголовок: X-API-Key: <key>
- В проде рекомендуется отключить без необходимости.

Документ не утверждает конкретный JWT провайдер. Это определяется реализацией. Не могу подтвердить это.

### 3.3 Авторизация (RBAC)
Роли:
- user
- support
- admin

Права проверяются на сервере. В ответах 403 возвращается унифицированная ошибка.

### 3.4 Подпись вебхуков
Вебхуки подписываются HMAC SHA-256:
- Заголовок: X-CSMarket-Signature: v1=<hex>
- Подпись вычисляется от сырого тела запроса (raw body) с секретом webhook_secret.
- Заголовок: X-CSMarket-Timestamp: unix seconds
- Рекомендуемое окно допустимой рассинхронизации: 300 секунд.

Если вы не используете вебхуки, этот раздел можно игнорировать.

## 4. Идемпотентность

Для операций, создающих платежи и ордера, поддерживается ключ идемпотентности:
- Заголовок: Idempotency-Key: <uuid or unique string>

Правило:
- Одинаковый ключ для одного пользователя и одного маршрута должен возвращать один и тот же результат в пределах TTL.
TTL определяется реализацией. Не могу подтвердить это.

## 5. Rate limiting

Сервер может ограничивать частоту запросов.
Рекомендуемые заголовки (если включено):
- X-RateLimit-Limit
- X-RateLimit-Remaining
- X-RateLimit-Reset

Конкретные лимиты зависят от окружения. Не могу подтвердить это.

## 6. Общая модель ответов

### 6.1 Успешный ответ
Типовой формат:
- data: объект или массив
- meta: служебные поля (пагинация, trace_id)

Пример:
{
  "data": { ... },
  "meta": { "trace_id": "01HR..." }
}

### 6.2 Ошибка
Единый формат:
{
  "error": {
    "code": "string",
    "message": "string",
    "details": { "any": "json" }
  },
  "meta": {
    "trace_id": "string"
  }
}

code должен быть стабильным контрактом.

Коды HTTP:
- 400 bad_request
- 401 unauthorized
- 403 forbidden
- 404 not_found
- 409 conflict
- 422 validation_failed
- 429 rate_limited
- 500 internal_error
- 503 service_unavailable

### 6.3 Traceability
meta.trace_id возвращается всегда, если включена трассировка. Если не включена, не могу подтвердить это.

## 7. Пагинация и сортировка

### 7.1 Cursor pagination (рекомендуется)
Запрос:
- limit: integer (1..100)
- cursor: string (optional)

Ответ meta:
- next_cursor: string | null
- limit: integer

### 7.2 Сортировка
- sort: поле, например created_at
- order: asc | desc

Конкретный набор полей сортировки для каждого ресурса указан в соответствующем разделе.

## 8. Сущности (контракт)

### 8.1 User
Поля:
- id: string (uuid)
- username: string
- created_at: string (ISO 8601)
- status: active | blocked

### 8.2 SteamAccount (привязка)
Поля:
- id: string (uuid)
- steam_id: string
- display_name: string
- linked_at: string

Не утверждается механизм привязки (OAuth, подпись, код). Не могу подтвердить это.

### 8.3 Asset (скин или предмет)
Поля:
- asset_id: string
- app_id: integer
- class_id: string
- instance_id: string
- name: string
- icon_url: string (URL)
- tradable: boolean
- marketable: boolean
- tags: array of { key, value }

### 8.4 InventoryItem
Поля:
- inventory_item_id: string (uuid)
- owner_user_id: string (uuid)
- asset: Asset
- state: available | locked | in_trade | sold
- updated_at: string

### 8.5 Listing (листинг на продажу)
Поля:
- listing_id: string (uuid)
- seller_user_id: string (uuid)
- inventory_item_id: string (uuid)
- price: { amount: string, currency: "RUB" | "USD" | "EUR" | "USDT" }
- status: active | paused | sold | cancelled | expired
- created_at: string
- updated_at: string

### 8.6 Order (покупка)
Поля:
- order_id: string (uuid)
- buyer_user_id: string (uuid)
- listing_id: string (uuid)
- amount: { amount: string, currency: "RUB" | "USD" | "EUR" | "USDT" }
- status: pending_payment | paid | delivering | delivered | cancelled | refunded | failed
- created_at: string
- updated_at: string

### 8.7 PaymentIntent (криптоплатёж)
Поля:
- payment_intent_id: string (uuid)
- order_id: string (uuid)
- method: "BTC" | "ETH" | "TON"
- amount: { amount: string, currency: "BTC" | "ETH" | "TON" }
- address: string
- status: created | awaiting_confirmations | confirmed | expired | failed
- expires_at: string
- created_at: string

Адреса и суммы являются частью реализации. Документ задаёт контракт полей, но не утверждает провайдера. Не могу подтвердить это.

## 9. Endpoints

Все маршруты ниже относительно /api/v1

### 9.1 Health

GET /health
Ответ 200:
{
  "data": {
    "status": "ok",
    "version": "string",
    "time": "2026-02-13T12:34:56Z"
  },
  "meta": { "trace_id": "..." }
}

GET /ready
Используется для orchestration readiness.
Ответ 200 или 503.

### 9.2 Auth

POST /auth/login
Body:
{
  "username": "string",
  "password": "string"
}
Ответ 200:
{
  "data": {
    "access_token": "string",
    "token_type": "Bearer",
    "expires_in": 3600
  },
  "meta": { "trace_id": "..." }
}

POST /auth/logout
Требует Authorization.
Ответ 204 без тела.

POST /auth/refresh
Body:
{
  "refresh_token": "string"
}
Ответ 200 аналогичен login.

Документ не утверждает, что refresh_token хранится в cookie или body, это зависит от реализации. Не могу подтвердить это.

### 9.3 Users

GET /me
Требует Authorization.
Ответ 200:
{
  "data": {
    "id": "uuid",
    "username": "string",
    "status": "active",
    "created_at": "ISO"
  },
  "meta": { "trace_id": "..." }
}

PATCH /me
Требует Authorization.
Body (пример):
{
  "username": "string"
}
Ответ 200: обновлённый User.

### 9.4 Steam account linking

GET /me/steam
Ответ 200:
{
  "data": {
    "linked": true,
    "steam_account": {
      "id": "uuid",
      "steam_id": "string",
      "display_name": "string",
      "linked_at": "ISO"
    }
  },
  "meta": { "trace_id": "..." }
}

POST /me/steam/link
Body:
{
  "link_token": "string"
}
Ответ 200:
{
  "data": { "linked": true },
  "meta": { "trace_id": "..." }
}
Если link_token неверный: 422 validation_failed.

Документ не определяет способ получения link_token. Не могу подтвердить это.

POST /me/steam/unlink
Ответ 200:
{
  "data": { "linked": false },
  "meta": { "trace_id": "..." }
}

### 9.5 Inventory

GET /inventory
Query:
- limit: 1..100
- cursor: string
- state: available | locked | in_trade | sold (optional)
- app_id: integer (optional)
Ответ 200:
{
  "data": [InventoryItem],
  "meta": {
    "next_cursor": "string or null",
    "limit": 50,
    "trace_id": "..."
  }
}

POST /inventory/sync
Запускает синхронизацию инвентаря.
Ответ 202:
{
  "data": { "sync_job_id": "uuid" },
  "meta": { "trace_id": "..." }
}

GET /inventory/sync/{sync_job_id}
Ответ 200:
{
  "data": {
    "sync_job_id": "uuid",
    "status": "queued | running | done | failed",
    "updated_at": "ISO"
  },
  "meta": { "trace_id": "..." }
}

Статусы sync_job зависят от очередей и реализации. Не могу подтвердить это.

### 9.6 Catalog (поиск предметов)

GET /catalog/assets
Query:
- q: string (optional)
- app_id: integer (optional)
- limit: 1..100
- cursor: string
- sort: name | popularity | updated_at
- order: asc | desc
Ответ 200:
{
  "data": [Asset],
  "meta": { "next_cursor": "...", "limit": 50, "trace_id": "..." }
}

Поле popularity требует метрик и источника данных. Если не реализовано, не могу подтвердить это.

### 9.7 Listings

POST /listings
Требует Authorization.
Headers:
- Idempotency-Key: string (recommended)
Body:
{
  "inventory_item_id": "uuid",
  "price": { "amount": "string", "currency": "RUB" }
}
Ответ 201:
{
  "data": Listing,
  "meta": { "trace_id": "..." }
}

GET /listings
Query:
- limit, cursor
- status: active | paused | sold | cancelled | expired (optional)
- seller_user_id: uuid (optional, для админов)
- sort: created_at | price
- order: asc | desc
Ответ 200: список Listing.

GET /listings/{listing_id}
Ответ 200: Listing.

PATCH /listings/{listing_id}
Body:
{
  "status": "paused | active",
  "price": { "amount": "string", "currency": "RUB" }
}
Ответ 200: Listing.

DELETE /listings/{listing_id}
Отмена листинга.
Ответ 204.

Конкретные правила смены статусов зависят от бизнес-логики. Не могу подтвердить это.

### 9.8 Orders

POST /orders
Требует Authorization.
Headers:
- Idempotency-Key: string (required for production)
Body:
{
  "listing_id": "uuid"
}
Ответ 201:
{
  "data": Order,
  "meta": { "trace_id": "..." }
}

GET /orders
Query:
- limit, cursor
- status: pending_payment | paid | delivering | delivered | cancelled | refunded | failed
- sort: created_at
- order: asc | desc
Ответ 200: список Order.

GET /orders/{order_id}
Ответ 200: Order.

POST /orders/{order_id}/cancel
Отмена заказа (если допустимо).
Ответ 200:
{
  "data": Order,
  "meta": { "trace_id": "..." }
}

### 9.9 Payments (BTC, ETH, TON)

POST /orders/{order_id}/payment_intents
Требует Authorization.
Headers:
- Idempotency-Key: string (required)
Body:
{
  "method": "BTC"
}
Ответ 201:
{
  "data": PaymentIntent,
  "meta": { "trace_id": "..." }
}

GET /payment_intents/{payment_intent_id}
Ответ 200: PaymentIntent.

POST /payment_intents/{payment_intent_id}/refresh
Перевыпуск или обновление статуса у провайдера (если поддерживается).
Ответ 200: PaymentIntent.

Документ не утверждает схему подтверждений сети и количество confirmations. Это зависит от риск-политики и реализации. Не могу подтвердить это.

### 9.10 Delivery (передача предмета)

POST /orders/{order_id}/deliver
Требует role: support или admin.
Body:
{
  "delivery_reference": "string",
  "note": "string"
}
Ответ 200:
{
  "data": {
    "order_id": "uuid",
    "status": "delivered",
    "delivered_at": "ISO"
  },
  "meta": { "trace_id": "..." }
}

Если доставка автоматическая, этот endpoint может использоваться внутренними сервисами. Не могу подтвердить это.

### 9.11 Webhooks

POST /webhooks/register
Role: admin.
Body:
{
  "url": "https://client.example/webhook",
  "events": ["order.paid", "order.delivered", "payment.confirmed"],
  "secret": "string"
}
Ответ 201:
{
  "data": { "webhook_id": "uuid" },
  "meta": { "trace_id": "..." }
}

GET /webhooks
Role: admin.
Ответ 200:
{
  "data": [
    {
      "webhook_id": "uuid",
      "url": "string",
      "events": ["string"],
      "created_at": "ISO"
    }
  ],
  "meta": { "trace_id": "..." }
}

DELETE /webhooks/{webhook_id}
Role: admin.
Ответ 204.

Список событий:
- order.paid
- order.cancelled
- order.delivered
- payment.confirmed
- payment.failed
- listing.created
- listing.sold

Если часть событий не реализована, не могу подтвердить это.

### 9.12 Admin

GET /admin/users
Role: admin.
Query:
- limit, cursor
- q: string (поиск по username)
Ответ 200: список User.

POST /admin/users/{user_id}/block
Role: admin.
Body:
{
  "reason": "string"
}
Ответ 200: User со status blocked.

POST /admin/users/{user_id}/unblock
Role: admin.
Ответ 200: User.

GET /admin/metrics
Role: admin.
Ответ 200:
{
  "data": {
    "orders_total": 0,
    "orders_paid": 0,
    "gmv": { "amount": "0", "currency": "RUB" }
  },
  "meta": { "trace_id": "..." }
}

Эти метрики требуют определения источника данных и окна агрегации. Если не реализовано, не могу подтвердить это.

## 10. Валидация и форматы

### 10.1 Денежные значения
- amount всегда строка, чтобы избежать ошибок float
- Валюта фиксирована перечислением

### 10.2 UUID
- Все идентификаторы ресурсов UUID v4 в строковом виде

### 10.3 URL
- icon_url и webhook url должны быть валидными URL

## 11. Примеры ошибок

401 unauthorized:
{
  "error": {
    "code": "unauthorized",
    "message": "Missing or invalid token",
    "details": {}
  },
  "meta": { "trace_id": "..." }
}

422 validation_failed:
{
  "error": {
    "code": "validation_failed",
    "message": "Request validation failed",
    "details": {
      "fields": {
        "price.amount": "Must be a positive decimal string"
      }
    }
  },
  "meta": { "trace_id": "..." }
}

409 conflict (например, inventory item уже в продаже):
{
  "error": {
    "code": "conflict",
    "message": "Resource state conflict",
    "details": { "reason": "inventory_item_not_available" }
  },
  "meta": { "trace_id": "..." }
}

## 12. OpenAPI

Рекомендуется поддерживать OpenAPI 3.1 спецификацию как машинно-читаемую версию контракта:
- GET /openapi.json
- GET /docs (Swagger UI)

Если эти маршруты не включены в прод окружении, не могу подтвердить это.
