# realtime-events
# CSMarket Real-time Events

## 1. Назначение

Этот документ задает единый промышленный стандарт событий реального времени для CSMarket: формат сообщений, каналы доставки до клиентов, внутреннюю маршрутизацию, гарантии, безопасность и наблюдаемость.

## 2. Термины и принципы

Событие это неизменяемая запись о факте, произошедшем в системе. Клиенты получают события через real-time канал и обновляют UI без опроса.

Для унификации межсервисных событий используется CloudEvents как стандарт описания event data для интероперабельности. :contentReference[oaicite:0]{index=0}

Для машинно-читаемого описания асинхронных API используется AsyncAPI спецификация. :contentReference[oaicite:1]{index=1}

## 3. Транспорт до клиента

### 3.1 WebSocket

WebSocket используется для двустороннего канала клиент сервер, включая интерактивные сценарии и подтверждения доставки на уровне приложения. Протокол описан в RFC 6455. :contentReference[oaicite:2]{index=2}

### 3.2 Server-Sent Events

SSE используется для односторонней доставки сервер клиент по долгоживущему HTTP соединению через интерфейс EventSource, определенный в HTML Standard. :contentReference[oaicite:3]{index=3}

Правило выбора транспорта
WebSocket по умолчанию для WebApp и Desktop, SSE допускается для простых read-only лент и дашбордов.

## 4. Внутреннее распространение событий

### 4.1 Kafka как основной event streaming

Kafka рассматривается как основной брокер для высоконагруженных потоков. Базовые понятия producers, consumers, topics и partitions описаны в официальной документации Apache Kafka. :contentReference[oaicite:4]{index=4}

### 4.2 Redis Streams как легковесный брокер

Redis Streams допускается для очередей и fan-out в рамках инфраструктуры, где Redis уже присутствует. Команды XADD и XREADGROUP являются базовыми для записи в stream и чтения в consumer group. :contentReference[oaicite:5]{index=5}

### 4.3 PostgreSQL LISTEN/NOTIFY как минимальный pubsub

PostgreSQL допускается как минимальный pubsub для легких уведомлений, когда брокер недоступен или избыточен. LISTEN регистрирует подписку на канал, NOTIFY рассылает уведомления с payload. :contentReference[oaicite:6]{index=6}

Политика
В production при росте нагрузки приоритет Kafka, Redis Streams для внутренних задач и простых конвейеров, LISTEN/NOTIFY только для низкого трафика и сигналов.

## 5. Каналы событий CSMarket

Каналы это логические темы. Имена фиксируются и считаются частью контракта.

Рекомендуемая схема именования
csmarket.<domain>.<entity>.<action>.v1

Примеры
csmarket.market.listing.created.v1
csmarket.market.listing.updated.v1
csmarket.market.listing.removed.v1
csmarket.trade.order.created.v1
csmarket.trade.order.filled.v1
csmarket.trade.order.canceled.v1
csmarket.wallet.deposit.confirmed.v1
csmarket.wallet.withdrawal.approved.v1
csmarket.user.profile.updated.v1
csmarket.security.session.revoked.v1
csmarket.system.health.degraded.v1

## 6. Формат события

### 6.1 Базовая обертка CloudEvents

Каждое событие передается в формате CloudEvents. Это обеспечивает единый набор атрибутов, независимый от транспорта. :contentReference[oaicite:7]{index=7}

Обязательные поля на уровне контракта
specversion: "1.0"
id: уникальный идентификатор события
source: источник события в виде URI или namespace
type: тип события из списка каналов
time: время генерации в RFC 3339
datacontenttype: "application/json"
data: полезная нагрузка доменного события

Примечание
Точные требования CloudEvents определяются спецификацией CloudEvents. :contentReference[oaicite:8]{index=8}

### 6.2 Расширения CSMarket

Дополнительные атрибуты для корреляции и эксплуатации
subject: идентификатор сущности, например listing_id
traceparent: W3C trace context, если используется
tenant: идентификатор пространства, если есть multi-tenant
authz: минимальный набор claim метаданных для аудита

## 7. Гарантии и обработка ошибок

### 7.1 Доставка и подтверждения

Уровень системы
Внешним клиентам предоставляется best-effort доставка в реальном времени, а строгая консистентность достигается через REST или повторный запрос состояния.

Уровень внутреннего брокера
Kafka или Redis Streams используются для at-least-once обработки, а идемпотентность обязательна на consumer стороне.

### 7.2 Идемпотентность

Каждый consumer обязан обрабатывать событие идемпотентно по полю id. Повторная доставка не должна приводить к повторным побочным эффектам.

### 7.3 Порядок

Порядок гарантируется только в пределах ключа партиционирования
Kafka упорядочивает сообщения внутри partition, поэтому ключ должен быть стабильным, например listing_id или order_id. Концепция topic partitions описана в документации Kafka. :contentReference[oaicite:9]{index=9}

Для Redis Streams порядок чтения определяется порядком записей в stream, а распределение по consumer group задает обработку без дубликатов между consumers, что соответствует модели XREADGROUP. :contentReference[oaicite:10]{index=10}

### 7.4 Ретраи и DLQ

Ретраи
Используется экспоненциальная задержка и ограничение по попыткам.

DLQ
События, не обработанные после лимита попыток, отправляются в dlq канал
csmarket.dlq.<original_type>.v1

## 8. Безопасность

Транспорт
Для WebSocket используется wss, для SSE используется HTTPS.

Доступ
Подписка на каналы требует авторизации и серверной фильтрации событий по правам пользователя.

Изоляция
События с персональными данными не транслируются в широкие каналы; применяется принцип минимально необходимой информации.

## 9. Наблюдаемость

OpenTelemetry используется как единый стандарт телеметрии. Спецификация описывает сигналы и компоненты экосистемы, включая логи и корреляцию с Resource и контекстом. :contentReference[oaicite:11]{index=11}

Требования
Каждое публикуемое событие логируется структурно с event.id, event.type, source, subject
Каждый consumer пишет метрики обработок, ошибок и latency
Трассировка прокидывает корреляцию от входящего запроса до публикации события

## 10. Контракты и совместимость

AsyncAPI документ фиксирует каналы, payload schemas и bindings для выбранных протоколов. AsyncAPI является протокол-агностичной спецификацией для message-driven API. :contentReference[oaicite:12]{index=12}

Версионирование
type и канал содержат версию vN
breaking изменения только через новую версию канала и схемы

## 11. Тестирование

Контрактные тесты
Проверка CloudEvents атрибутов, уникальности id, совместимости схем

Интеграционные тесты
Публикация в брокер и доставка до WebSocket или SSE клиента

Нагрузочные тесты
Оценка задержки публикации и fan-out при целевых пиках

## 12. Минимальные примеры payload

listing.created
data:
  listing_id: string
  app_id: int
  market_hash_name: string
  price: object
  seller_id: string
  created_at: string

order.filled
data:
  order_id: string
  listing_id: string
  buyer_id: string
  seller_id: string
  fill_price: object
  filled_at: string
