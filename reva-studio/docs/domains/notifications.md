# Notifications Domain

## Статус документа

- Статус: Accepted
- Контекст: Reva Studio
- Область: `notifications`
- Уровень: Domain Design
- Тип документа: Bounded Context / Domain Contract
- Аудитория: backend, bot, admin, analytics, devops, product
- Последнее обновление: 2026-03-23

---

## 1. Назначение домена

Домен `notifications` отвечает за создание, планирование, доставку, повторную отправку, аудит и анализ пользовательских и внутренних уведомлений в Reva Studio.

Домен нужен для следующих бизнес-задач:

- уведомление клиента о записи, переносе, отмене и подтверждении визита;
- уведомление мастера о новых, изменённых и отменённых слотах;
- отправка сервисных сообщений по оплатам, бонусам, акциям и системным событиям;
- централизованное управление шаблонами, предпочтениями пользователя и политиками доставки;
- обеспечение трассируемости и управляемости доставки через единый журнал событий.

Этот документ фиксирует именно доменную модель и инварианты. Конкретные SDK, HTTP-клиенты, очереди и провайдеры относятся к инфраструктурному слою.

---

## 2. Границы bounded context

Домен `notifications` включает:

- подготовку сообщения из доменного события;
- определение получателей;
- выбор канала доставки;
- применение пользовательских предпочтений;
- планирование времени отправки;
- дедупликацию и идемпотентность;
- доставку, повторы, фиксацию статуса;
- аудит и метрики.

Домен `notifications` не включает:

- бизнес-логику записи, оплаты, loyalty и маркетинга;
- хранение профиля пользователя как master-source;
- построение UI админки;
- реализацию конкретного Telegram/SMTP/SMS провайдера.

---

## 3. Зависимости от соседних доменов

`notifications` получает входные события и команды от следующих доменов:

- `bookings`
- `users`
- `staff`
- `payments`
- `loyalty`
- `marketing`
- `auth`
- `admin`
- `analytics`

Обратные контракты домена `notifications`:

- публикация фактов доставки в `analytics`;
- публикация технических событий в `observability`;
- публикация ошибок доставки в `admin` и внутренние каналы оповещения;
- предоставление истории уведомлений для карточки клиента, записи и мастера.

---

## 4. Цели качества

Домен проектируется под следующие свойства:

- предсказуемость доставки;
- идемпотентность операций отправки;
- наблюдаемость;
- безопасную повторную обработку;
- изоляцию от конкретного канала;
- расширяемость по новым каналам и новым типам сообщений;
- управляемую деградацию при частичных сбоях.

---

## 5. Ключевые термины

### Notification
Домашняя сущность уведомления. Представляет намерение доставить конкретное сообщение конкретному получателю по одному или нескольким каналам.

### Notification Event
Доменный факт, из которого может быть построено одно или несколько уведомлений. Примеры: `booking_created`, `booking_confirmed`, `booking_cancelled`, `payment_succeeded`.

### Recipient
Целевой получатель уведомления. Это может быть клиент, мастер, администратор или внутренняя системная группа.

### Channel
Способ доставки. На старте проекта поддерживаются:

- telegram
- email
- push
- internal

### Template
Версионируемый шаблон сообщения с параметрами рендеринга.

### Delivery Attempt
Одна техническая попытка доставить уведомление.

### Notification Preference
Набор правил, определяющих, какие типы уведомлений и в каких каналах разрешены конкретному пользователю.

### Scheduled Notification
Уведомление, у которого есть время активации отправки в будущем.

---

## 6. Бизнес-инварианты

1. Одно и то же доменное событие не должно порождать бесконтрольные дубликаты уведомлений.
2. Статус уведомления должен быть восстанавливаем по журналу попыток доставки.
3. Пользовательские предпочтения применяются до постановки сообщения в доставку.
4. Канал доставки выбирается на основании:
   - типа события;
   - критичности;
   - доступности контакта;
   - пользовательских ограничений;
   - бизнес-политики.
5. Шаблон должен быть версионируемым, чтобы исторически отправленные сообщения можно было объяснить и воспроизвести.
6. Критические сервисные уведомления могут обходить маркетинговые opt-out правила, но только если это явно задано политикой и типом уведомления.
7. Любая повторная отправка должна быть безопасна относительно уже зафиксированного результата.

---

## 7. Классификация уведомлений

### 7.1 По назначению

- Transactional:
  - подтверждение записи;
  - перенос;
  - отмена;
  - напоминание;
  - уведомление по оплате;
  - изменение бонусного баланса;
  - подтверждение действия в аккаунте.

- Operational:
  - внутренние уведомления мастеру;
  - уведомления администратору;
  - алерты по сбоям интеграций;
  - сообщения о переполнении очередей;
  - сообщения о нарушении SLA.

- Marketing:
  - акции;
  - реактивационные кампании;
  - персональные предложения;
  - промо-рассылки.

### 7.2 По критичности

- critical
- high
- normal
- low

### 7.3 По времени доставки

- immediate
- scheduled
- recurring
- deadline-bound

---

## 8. Каналы доставки

### 8.1 Telegram

Основной пользовательский канал на старте Reva Studio.

Причины выбора:

- прямое соответствие продукту на базе Telegram-бота;
- быстрый time-to-delivery;
- низкий трение-фактор для клиента;
- единая точка коммуникации с записью, бонусами и напоминаниями.

Технологический факт: Telegram Bot API является HTTP-based интерфейсом для разработчиков ботов, что делает его естественным кандидатом на роль одного из инфраструктурных провайдеров канала `telegram`. Источник: [Telegram Bot API](https://core.telegram.org/bots/api).

### 8.2 Email

Резервный или дополнительный канал для:

- чеков и подтверждений;
- юридически или организационно значимых сообщений;
- fallback-сценариев;
- длинных сообщений и сводок.

### 8.3 Push

Поддерживается как расширяемый канал для будущего mobile/web-приложения.

### 8.4 Internal

Внутренний канал для:

- admin dashboard;
- audit trail;
- staff feed;
- оперативных сервисных алертов.

---

## 9. Доменная модель

## 9.1 Aggregate: Notification

Рекомендуемая модель агрегата:

- `notification_id`
- `tenant_id`
- `event_type`
- `event_id`
- `category`
- `priority`
- `recipient_type`
- `recipient_id`
- `channel`
- `template_code`
- `template_version`
- `locale`
- `payload`
- `deduplication_key`
- `scheduled_at`
- `expires_at`
- `status`
- `provider`
- `provider_message_id`
- `last_error_code`
- `last_error_message`
- `created_at`
- `updated_at`
- `sent_at`
- `delivered_at`
- `failed_at`
- `cancelled_at`

### 9.2 Aggregate states

Допустимые состояния:

- `created`
- `scheduled`
- `queued`
- `processing`
- `sent`
- `delivered`
- `failed`
- `cancelled`
- `expired`
- `suppressed`

### 9.3 DeliveryAttempt

Отдельная сущность или child-record:

- `attempt_id`
- `notification_id`
- `attempt_no`
- `started_at`
- `finished_at`
- `provider`
- `request_snapshot`
- `response_snapshot`
- `status`
- `error_code`
- `error_message`
- `latency_ms`

### 9.4 NotificationPreference

- `user_id`
- `channel`
- `category`
- `enabled`
- `quiet_hours_from`
- `quiet_hours_to`
- `locale`
- `timezone`
- `updated_at`

### 9.5 Template

- `template_code`
- `version`
- `channel`
- `locale`
- `subject`
- `body`
- `variables_schema`
- `is_active`
- `created_at`

---

## 10. Базовые доменные события

Домен `notifications` должен уметь реагировать минимум на следующие события:

### Клиентские

- `booking_created`
- `booking_confirmed`
- `booking_rescheduled`
- `booking_cancelled`
- `appointment_reminder_due`
- `payment_succeeded`
- `payment_failed`
- `loyalty_points_accrued`
- `loyalty_points_redeemed`
- `user_registered`
- `password_reset_requested`

### Внутренние

- `staff_schedule_changed`
- `shift_cancelled`
- `provider_degraded`
- `notification_delivery_failed`
- `notification_dlq_threshold_reached`

---

## 11. Правила маршрутизации

### 11.1 Пример маршрутизации по умолчанию

- `booking_created`:
  - client -> telegram
  - staff -> internal

- `booking_confirmed`:
  - client -> telegram
  - optional fallback -> email

- `appointment_reminder_due`:
  - client -> telegram
  - fallback при недоставке -> email

- `payment_succeeded`:
  - client -> telegram
  - optional email receipt

- `provider_degraded`:
  - admin -> internal
  - on-call -> internal or email

### 11.2 Принципы выбора канала

- transactional уведомления имеют приоритет над marketing;
- канал должен поддерживать нужный формат сообщения;
- канал должен быть разрешён настройками пользователя;
- канал должен быть доступен по контактным данным;
- при нескольких разрешённых каналах должен использоваться приоритетный маршрут;
- fallback включается только для типов сообщений, где это разрешено политикой.

---

## 12. Идемпотентность и дедупликация

Для каждого уведомления должен вычисляться `deduplication_key`.

Рекомендуемая формула:

`{tenant_id}:{event_type}:{event_id}:{recipient_id}:{channel}:{template_version}`

Назначение ключа:

- предотвратить повторную постановку одинакового уведомления;
- сделать безопасным повтор обработки входного события;
- исключить массовые дубли при сетевых и worker-сбоях.

Правило:

- уникальность должна обеспечиваться на уровне базы данных;
- повторно пришедшее идентичное событие должно либо вернуть существующую запись, либо быть мягко подавлено в `suppressed`.

---

## 13. Планирование доставки

Поддерживаются 3 режима:

### 13.1 Immediate
Уведомление должно быть отправлено без отложенного окна.

### 13.2 Scheduled
Уведомление должно ждать `scheduled_at`.

Примеры:

- reminder за 24 часа;
- reminder за 2 часа;
- follow-up после визита через 1 день;
- реактивация через 30 дней без записи.

### 13.3 Recurring
Используется для внутренних operational-уведомлений и маркетинговых кампаний, если их планирование вынесено в уровень orchestration.

---

## 14. Тихие часы и пользовательские предпочтения

Домен должен поддерживать quiet hours.

Минимальные правила:

- маркетинговые уведомления не отправляются в quiet hours;
- transactional-уведомления могут быть отправлены в quiet hours, если они критичны по бизнес-логике;
- quiet hours интерпретируются в таймзоне пользователя;
- если таймзона пользователя неизвестна, применяется политика tenant default.

---

## 15. Шаблоны

Шаблоны обязательны для production-режима.

Требования:

- версионирование;
- локализация;
- поддержка безопасного рендеринга переменных;
- разделение `subject` и `body` там, где это применимо;
- возможность быстрого отключения шаблона;
- возможность предпросмотра;
- обратимая связь с отправленным сообщением через `template_code + version`.

Минимальный набор переменных для validation:

- все обязательные переменные должны быть описаны схемой;
- рендер не должен происходить с отсутствующими обязательными ключами;
- payload должен быть сериализуемым;
- payload не должен содержать секретов провайдера.

---

## 16. Очереди и delivery pipeline

Рекомендуемый pipeline:

1. Внешний домен публикует событие.
2. `notifications` выполняет policy evaluation.
3. Рассчитывается список получателей.
4. Подбираются каналы.
5. Генерируются записи `Notification`.
6. Для готовых к отправке уведомлений создаётся задача доставки.
7. Worker выполняет попытку доставки.
8. Результат фиксируется в `DeliveryAttempt`.
9. Агрегат `Notification` переводится в новое состояние.
10. В `analytics` и `observability` публикуются производные события.

Если для исполнения используется Celery, его официальный механизм `retry()` переиспользует тот же task-id и повторно ставит задачу в ту же очередь, что полезно для управляемых повторов recoverable failures. Источник: [Celery Tasks: Retrying](https://docs.celeryq.dev/en/main/userguide/tasks.html).

Если используется Celery publish retry, официальная документация отдельно указывает, что повтор публикации сообщений при ошибках соединения можно настраивать через `task_publish_retry` и `task_publish_retry_policy`. Источник: [Celery Calling Tasks: Message Sending Retry](https://docs.celeryq.dev/en/main/userguide/calling.html).

---

## 17. Конкурентная обработка

При многоворкерной модели выборка записей на доставку должна быть конкурентно-безопасной.

Рекомендуемый подход на PostgreSQL:

- выбирать пачку записей с блокировкой строк;
- использовать `FOR UPDATE SKIP LOCKED`, чтобы параллельные воркеры не ждали друг друга на уже захваченных строках;
- фиксировать переход `queued -> processing` в одной транзакции.

Официальная документация PostgreSQL указывает, что `SKIP LOCKED` позволяет пропускать строки, которые не удаётся сразу заблокировать, вместо ожидания. Это подходит для очередеподобной конкурентной обработки. Источник: [PostgreSQL SELECT](https://www.postgresql.org/docs/current/sql-select.html).

---

## 18. Повторы и ошибки

Ошибки делятся на 3 класса:

### 18.1 Permanent failure
Повтор не нужен.

Примеры:

- recipient отсутствует;
- канал отключён политикой;
- шаблон невалиден;
- payload не проходит validation;
- объект уже истёк.

### 18.2 Recoverable failure
Нужен повтор с backoff.

Примеры:

- временный сетевой сбой;
- timeout провайдера;
- rate limiting;
- кратковременная деградация внешнего API.

### 18.3 Unknown failure
Требует ограниченного числа повторов и escalation.

Правила повторов:

- exponential backoff;
- jitter;
- верхний предел числа попыток;
- перевод в `failed` после исчерпания;
- публикация технического события для on-call/internal alerting.

---

## 19. Подавление уведомлений

Уведомление может быть переведено в `suppressed`, если:

- пользователь запретил этот тип канала;
- действует quiet hours для non-critical категории;
- событие признано дублем;
- сущность-источник более не актуальна;
- сообщение стало бессмысленным из-за последующего доменного события.

Пример:
Если запись была создана, затем подтверждена, а затем отменена до момента отправки reminder, reminder должен быть подавлен, а не отправлен.

---

## 20. Истечение срока актуальности

Каждое уведомление может иметь `expires_at`.

Если к моменту наступления попытки доставки текущее время больше `expires_at`, уведомление переводится в `expired`.

Примеры сообщений с естественным TTL:

- напоминание о визите;
- подтверждение окна оплаты;
- одноразовый код действия;
- операционный алерт, актуальный только в пределах инцидента.

---

## 21. Аудит и трассируемость

Для production-эксплуатации обязательны:

- история статусов уведомления;
- история попыток доставки;
- ссылка на исходное доменное событие;
- provider request/response snapshot без секретов;
- correlation_id;
- causation_id;
- actor_id, если уведомление было инициировано явно из admin;
- отметка версии шаблона.

Цель аудита:

- объяснимость доставки;
- разбор жалоб клиента;
- расследование инцидентов;
- повторное воспроизведение цепочки событий.

---

## 22. Метрики и наблюдаемость

Минимальные метрики:

- notifications_created_total
- notifications_sent_total
- notifications_delivered_total
- notifications_failed_total
- notifications_suppressed_total
- notification_attempt_latency_ms
- notification_queue_lag_seconds
- notification_retry_total
- notification_dlq_size
- provider_error_rate
- template_render_failures_total

Минимальные срезы:

- channel
- event_type
- category
- priority
- provider
- tenant_id
- template_code

---

## 23. Безопасность и приватность

Обязательные правила:

- не хранить токены провайдеров в payload уведомлений;
- не логировать чувствительные персональные данные без необходимости;
- маскировать контактные данные в audit-выгрузках;
- ограничивать доступ к журналам уведомлений по RBAC;
- отделять маркетинговые согласия от сервисных уведомлений;
- поддерживать безопасное удаление или анонимизацию данных в рамках политики хранения.

---

## 24. Рекомендованная схема хранения

Ниже логическая схема, а не окончательный DDL.

### `notifications`

- `id`
- `tenant_id`
- `event_type`
- `event_id`
- `category`
- `priority`
- `recipient_type`
- `recipient_id`
- `channel`
- `template_code`
- `template_version`
- `locale`
- `payload_json`
- `deduplication_key`
- `scheduled_at`
- `expires_at`
- `status`
- `provider`
- `provider_message_id`
- `attempt_count`
- `last_error_code`
- `last_error_message`
- `created_at`
- `updated_at`
- `sent_at`
- `delivered_at`
- `failed_at`
- `cancelled_at`

Рекомендуемые ограничения:

- unique(`tenant_id`, `deduplication_key`)
- index(`status`, `scheduled_at`)
- index(`recipient_id`, `created_at`)
- index(`event_type`, `event_id`)
- index(`provider`, `status`)

### `notification_attempts`

- `id`
- `notification_id`
- `attempt_no`
- `started_at`
- `finished_at`
- `status`
- `provider`
- `request_snapshot_json`
- `response_snapshot_json`
- `error_code`
- `error_message`
- `latency_ms`

### `notification_preferences`

- `id`
- `user_id`
- `category`
- `channel`
- `enabled`
- `quiet_hours_from`
- `quiet_hours_to`
- `timezone`
- `locale`
- `updated_at`

### `notification_templates`

- `id`
- `template_code`
- `version`
- `channel`
- `locale`
- `subject`
- `body`
- `variables_schema_json`
- `is_active`
- `created_at`

---

## 25. Domain API

Рекомендуемые команды:

- `CreateNotification`
- `ScheduleNotification`
- `SendNotification`
- `RetryNotification`
- `CancelNotification`
- `SuppressNotification`
- `MarkNotificationDelivered`
- `MarkNotificationFailed`
- `UpdateNotificationPreference`
- `PreviewTemplate`

Рекомендуемые query use-cases:

- получить историю уведомлений пользователя;
- получить ленту уведомлений по записи;
- получить текущие сбои по каналам;
- получить статистику доставляемости;
- получить активные шаблоны.

---

## 26. Правила проектирования интеграции с Telegram

Для Telegram-канала домен должен опираться на инфраструктурный адаптер, а не на прямые вызовы из domain/application core.

Минимальный контракт адаптера:

- `send_text(...)`
- `send_media(...)`
- `delete_message(...)` если нужно
- `resolve_chat_binding(...)`
- `map_provider_error(...)`

Технологический факт: Telegram Bot API документирован как HTTP-based interface, а операции отправки сообщений предоставляются через методы Bot API. Источники:
- [Telegram Bot API](https://core.telegram.org/bots/api)
- [sendMessage](https://core.telegram.org/bots/api#sendmessage)

Внутреннее архитектурное правило Reva Studio:
домен не должен знать о формате HTTP-запроса, JSON-ответа или SDK провайдера.

---

## 27. Политика fallback

Fallback разрешён только для ограниченного множества событий.

Пример:

- `booking_confirmed`:
  - основной канал: telegram
  - fallback: email
- `appointment_reminder_due`:
  - основной канал: telegram
  - fallback: email только после подтверждённой технической ошибки
- `marketing_campaign_sent`:
  - fallback запрещён

Причина:
fallback увеличивает шанс доставки, но также увеличивает риск шумовой перегрузки пользователя.

---

## 28. Dead-letter стратегия

Уведомление или задача доставки попадает в DLQ или DLQ-equivalent, если:

- число повторов исчерпано;
- ошибка не классифицирована;
- provider response системно несовместим с контрактом;
- payload не может быть десериализован для безопасной повторной обработки.

Минимальные действия после попадания:

- зафиксировать финальный контекст;
- отправить internal alert;
- сделать запись доступной для ручного разбора;
- позволить controlled replay после исправления причины.

---

## 29. SLO и эксплуатационные цели

Целевые внутренние ориентиры домена:

- высокая успешность доставки transactional-сообщений;
- минимальная задержка для immediate-уведомлений;
- контролируемая глубина очередей;
- полная объяснимость статуса каждой попытки.

Численные SLO в этом документе не фиксируются, так как они должны определяться отдельно через product/ops соглашение и фактическую нагрузку проекта.

---

## 30. Минимальный сценарный каталог

### Сценарий A. Подтверждение записи
1. `bookings` публикует `booking_created`.
2. `notifications` создаёт уведомление клиенту.
3. Выбирается `telegram`.
4. Сообщение ставится в очередь.
5. Worker отправляет сообщение.
6. Статус обновляется до `sent` или `delivered`.

### Сценарий B. Напоминание за сутки
1. Планировщик публикует `appointment_reminder_due`.
2. Создаётся scheduled/immediate уведомление по окну.
3. Проверяются quiet hours и актуальность записи.
4. Выполняется отправка.
5. При recoverable failure применяется retry policy.

### Сценарий C. Отмена записи до reminder
1. Ранее созданное reminder-уведомление ещё не доставлено.
2. При событии `booking_cancelled` reminder пересматривается.
3. Reminder переводится в `suppressed` или `cancelled`.
4. Пользователю отправляется новое transactional-сообщение об отмене.

### Сценарий D. Деградация Telegram-провайдера
1. Ошибки доставки растут.
2. Канал фиксируется как degraded.
3. Критические уведомления переводятся на fallback-канал, если политика разрешает.
4. Operational-alert отправляется внутренним получателям.

---

## 31. Антипаттерны

Запрещённые решения:

- отправка уведомлений напрямую из доменов `bookings`, `payments`, `loyalty` без единого `notifications` контекста;
- отсутствие deduplication key;
- отсутствие истории попыток;
- шаблоны без версии;
- смешение маркетинговых и сервисных правил согласия;
- логирование секретов и полных персональных данных;
- жёсткая привязка domain logic к Telegram SDK;
- ручное повторение отправки без фиксации причин и попыток.

---

## 32. Рекомендации для реализации в Reva Studio

1. На старте считать `telegram` основным каналом для клиента.
2. Ввести `internal` канал для staff/admin с первого релиза.
3. Все уведомления создавать через единый application service.
4. Все шаблоны хранить версионируемо.
5. Все delivery attempts хранить отдельно от основного агрегата.
6. Ввести уникальный `deduplication_key` на уровне БД.
7. Обязательно иметь `scheduled_at`, `expires_at`, `priority`, `category`.
8. Закладывать fallback только там, где он реально улучшает продукт, а не шум.
9. Подключить метрики и audit до production-ввода.
10. Не смешивать orchestration campaign-логики и core delivery-логики в одном сервисе.

---

## 33. Итоговое архитектурное решение

Для Reva Studio домен `notifications` принимается как отдельный bounded context со следующими принципами:

- единая точка управления уведомлениями;
- канально-независимая доменная модель;
- шаблоны и предпочтения как first-class сущности;
- идемпотентная постановка и повторная обработка;
- конкурентно-безопасная delivery-модель;
- наблюдаемость, аудит и готовность к расширению.

---

## 34. Проверяемые внешние источники

1. Telegram Bot API:
   - https://core.telegram.org/bots/api
   - https://core.telegram.org/bots/api#sendmessage

2. Celery retry semantics:
   - https://docs.celeryq.dev/en/main/userguide/tasks.html
   - https://docs.celeryq.dev/en/main/userguide/calling.html

3. PostgreSQL row locking / SKIP LOCKED:
   - https://www.postgresql.org/docs/current/sql-select.html

---