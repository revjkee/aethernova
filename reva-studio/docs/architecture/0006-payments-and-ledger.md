# ADR 0006: Payments and Ledger

Status: Accepted

Date: 2026-03-22

Owners: Architecture

Related:
- 0001-system-overview.md
- 0002-modular-monolith-strategy.md
- 0003-tenancy-model.md
- 0004-auth-and-rbac.md
- 0005-booking-consistency.md

## TL;DR

Reva Studio внедряет событийно-ориентированный платёжный контур с внутренним ledger-слоем, который является единственным источником истины для финансового состояния домена. Внешний платёжный провайдер используется только как execution layer для авторизации, подтверждения, отмены, возвратов и доставки webhook-событий. Все изменения денежного состояния внутри платформы фиксируются через append-only ledger entries с обязательной идемпотентностью, корреляцией, аудитом и обратимой бизнес-логикой через compensating operations, а не через destructive updates.

Основные решения:
- внутренний ledger является canonical source of truth для балансов и движений;
- внешние provider events не меняют состояние напрямую, а проходят через верификацию, дедупликацию и application-level reconciliation;
- все mutating operations требуют idempotency key;
- webhook ingestion отделён от business posting;
- ledger entries неизменяемы после фиксации;
- коррекция ошибок выполняется только компенсирующими проводками;
- расчёт доступных сумм, задолженностей, возвратов и бонусов строится из записей ledger, а не из случайных полей в нескольких таблицах.

## Context

Платёжный контур Reva Studio должен поддерживать:
- приём оплаты за бронирования и услуги;
- частичную и полную предоплату;
- отмены и возвраты;
- бонусные начисления и списания;
- внутренние корректировки администратора с полным аудитом;
- повторную доставку webhook-событий от провайдера;
- безопасные повторные запросы клиента и фоновых воркеров;
- последующую интеграцию с несколькими платёжными провайдерами без переписывания доменной модели.

Проблемы, которые необходимо исключить:
- двойное списание из-за повторного запроса клиента;
- двойной учёт одного webhook-события;
- расхождение между состоянием платежа у провайдера и в домене;
- destructive updates, при которых теряется история изменений;
- невозможность объяснить происхождение итоговой суммы;
- финансовые состояния, вычисляемые из неканоничных флагов и nullable полей.

## Decision Drivers

Ключевые требования:
- идемпотентность всех mutating operations;
- строгая трассируемость денег и бонусов;
- возможность аудита и восстановления состояния на любую дату;
- устойчивость к сетевым сбоям, retry и out-of-order webhook delivery;
- расширяемость под несколько payment provider adapters;
- совместимость с асинхронной backend-архитектурой;
- ясное разделение domain state и provider state.

## Decision

### 1. Payment domain разделяется на четыре слоя

1. Domain layer
   Содержит доменные сущности, инварианты и use cases.

2. Ledger layer
   Является внутренним финансовым реестром платформы.

3. Provider adapter layer
   Инкапсулирует API внешнего провайдера и его webhook semantics.

4. Reconciliation and audit layer
   Отвечает за сверку, инциденты, исправления и финансовую наблюдаемость.

### 2. Внутренний ledger является единственным источником истины

Любая денежная операция внутри Reva Studio отражается в ledger. Статусы provider-side объектов не считаются достаточными для построения финального финансового состояния клиента, бронирования или студии.

Следствие:
- payment intent у провайдера не равен доменному `payment`;
- provider refund не равен внутреннему `refund settlement`, пока не проведена верификация и posting в ledger;
- баланс бонусов не хранится как произвольное число без истории движений.

### 3. Ledger реализуется как append-only

Запрещается менять сумму, направление и смысл уже проведённой ledger entry. Исправления делаются только новыми корректирующими проводками.

### 4. Внешний платёжный провайдер используется через port-adapter контракт

Версия v1 допускает основной adapter под Stripe, но архитектура не должна зависеть от конкретного вендора на уровне домена.

### 5. Все mutating requests обязаны иметь idempotency key

Это касается:
- создания платежа;
- capture;
- cancel;
- refund;
- применения бонусов;
- административных корректировок;
- retry-команд из фоновых задач.

### 6. Webhook ingestion строится как двухфазный pipeline

Фаза A:
- принять HTTP webhook;
- проверить подпись;
- сохранить raw event;
- записать dedup key;
- быстро вернуть успешный ответ, если событие уже обработано или поставлено в обработку.

Фаза B:
- асинхронно выполнить business processing;
- связать provider event с внутренними объектами;
- обновить payment aggregate;
- создать ledger postings;
- записать audit trail;
- при ошибке отправить событие в retry/reconciliation queue.

## Scope

Этот ADR покрывает:
- customer payments;
- prepayment flows;
- refunds;
- loyalty money-like movements;
- internal ledger postings;
- webhook processing;
- reconciliation.

Этот ADR не покрывает:
- налоговый учёт;
- бухгалтерский учёт юридического лица;
- payout orchestration для внешних контрагентов;
- full PCI scope design;
- multi-currency treasury management beyond domain readiness.

## Domain Model

### Core aggregates

#### Payment

Представляет внутреннюю бизнес-сущность оплаты.

Пример полей:
- `id`
- `tenant_id`
- `booking_id`
- `customer_id`
- `currency`
- `amount_total`
- `amount_authorized`
- `amount_captured`
- `amount_refunded`
- `status`
- `provider`
- `provider_payment_ref`
- `idempotency_key`
- `created_at`
- `updated_at`

Допустимые статусы:
- `created`
- `requires_action`
- `authorized`
- `partially_captured`
- `captured`
- `partially_refunded`
- `refunded`
- `canceled`
- `failed`

#### Refund

Отдельная сущность возврата, а не просто поле внутри payment.

Пример полей:
- `id`
- `tenant_id`
- `payment_id`
- `amount`
- `currency`
- `reason_code`
- `status`
- `provider_refund_ref`
- `requested_by`
- `created_at`
- `updated_at`

#### LedgerAccount

Счёт внутреннего реестра.

Минимальные типы:
- `customer_receivable`
- `cash_clearing`
- `provider_settlement_clearing`
- `refund_liability`
- `platform_revenue_pending`
- `platform_revenue_recognized`
- `bonus_liability`
- `bonus_expense`
- `adjustment`
- `writeoff`

#### LedgerEntry

Финансовое событие верхнего уровня.

Пример полей:
- `id`
- `tenant_id`
- `entry_type`
- `reference_type`
- `reference_id`
- `currency`
- `effective_at`
- `created_at`
- `idempotency_key`
- `correlation_id`
- `causation_id`
- `posted_by`
- `reversal_of_entry_id`
- `metadata_json`

#### LedgerPosting

Строка проводки внутри ledger entry.

Пример полей:
- `id`
- `entry_id`
- `account_code`
- `direction`
- `amount`
- `currency`
- `dimensions_json`

#### ProviderEvent

Сырой webhook или poll event от провайдера.

Пример полей:
- `id`
- `provider`
- `provider_event_id`
- `event_type`
- `signature_verified`
- `payload_json`
- `received_at`
- `processed_at`
- `processing_status`
- `dedup_hash`

#### PaymentAttempt

Попытка провести операцию на стороне провайдера.

Пример полей:
- `id`
- `payment_id`
- `operation`
- `provider_request_ref`
- `provider_response_ref`
- `idempotency_key`
- `status`
- `error_code`
- `error_message`
- `started_at`
- `finished_at`

## Financial Invariants

Ниже перечислены обязательные инварианты системы.

### Invariant 1
Сумма `amount_captured` не может превышать `amount_total`.

### Invariant 2
Сумма `amount_refunded` не может превышать `amount_captured`.

### Invariant 3
Каждая проведённая ledger entry должна быть сбалансирована по сумме внутри одной валюты.

### Invariant 4
Изменение финансового состояния домена допускается только через новую ledger entry.

### Invariant 5
Один и тот же provider event не может быть применён к домену более одного раза.

### Invariant 6
Один и тот же client mutation command с тем же idempotency key должен иметь тот же итоговый эффект.

### Invariant 7
Удаление финансовых записей запрещено на application уровне.

### Invariant 8
Refund может ссылаться только на существующий captured payment.

### Invariant 9
Любая административная корректировка требует actor identity, reason code и audit record.

### Invariant 10
Tenant isolation обязательна для всех payment, refund, ledger и audit объектов.

## State Separation

Необходимо явно разделять три состояния:

### 1. Provider state
Состояние у платёжного провайдера.

Примеры:
- payment intent created
- requires action
- succeeded
- charge refunded

### 2. Domain payment state
Бизнесовое состояние оплаты в Reva Studio.

Примеры:
- booking payment pending
- deposit confirmed
- payment partially refunded

### 3. Ledger state
Фактически проведённые денежные движения.

Примеры:
- customer receivable decreased
- cash clearing increased
- refund liability opened
- bonus liability consumed

Это разделение обязательно, потому что provider state и internal financial truth не совпадают по смыслу и времени.

## Canonical Flows

### Flow A. Create payment

1. Клиент инициирует оплату.
2. Backend создаёт `payment` в статусе `created`.
3. Генерируется `idempotency_key` и `correlation_id`.
4. Через provider adapter отправляется create payment intent request.
5. Создаётся `payment_attempt`.
6. Ответ провайдера сохраняется как provider-side reference.
7. Domain aggregate обновляется без ledger posting, если деньги ещё не подтверждены.
8. После подтверждённого provider event создаётся ledger entry.

### Flow B. Authorized then captured

Используется, если провайдер или бизнес-процесс поддерживает раздельную авторизацию и capture.

1. Payment переходит в `authorized`.
2. Ledger может не признавать выручку и не считать средства окончательно полученными до capture.
3. При capture создаётся posting, отражающий фактическое денежное движение.

### Flow C. Immediate successful payment

1. Provider сообщает об успешной оплате.
2. Webhook ingestion валидирует подпись и сохраняет raw event.
3. Асинхронный processor:
   - проверяет dedup;
   - находит payment;
   - проверяет, применялось ли событие ранее;
   - переводит payment в `captured`;
   - создаёт ledger entry;
   - фиксирует audit trail.

### Flow D. Partial refund

1. Пользователь или администратор инициирует возврат части суммы.
2. Система проверяет доступный refundable amount.
3. Создаётся `refund`.
4. Провайдеру отправляется refund request с новым idempotency key.
5. После подтверждения события создаётся refund ledger entry.
6. `amount_refunded` обновляется только после успешного posting.

### Flow E. Bonus payment or mixed settlement

Для смешанной оплаты:
- часть суммы закрывается бонусами;
- оставшаяся часть закрывается внешним платежом.

Это отражается двумя независимыми ledger entries, связанными одним `correlation_id`.

## Ledger Posting Rules

Ниже приведены примерные posting rules. Конкретные account codes могут быть уточнены в отдельной спецификации ledger chart.

### Case 1. Successful external payment capture

Цель:
- зафиксировать поступление денежных средств;
- закрыть клиентскую задолженность.

Пример:
- debit `cash_clearing`
- credit `customer_receivable`

### Case 2. Revenue recognition after service completion

Если бизнес решает отделить получение денег от признания выручки, то после выполнения услуги:
- debit `platform_revenue_pending`
- credit `platform_revenue_recognized`

Если такой слой не нужен на старте, допускается отложить его до отдельного ADR.

### Case 3. Refund

Пример:
- debit `refund_liability` или `customer_receivable`, зависит от выбранной финансовой схемы
- credit `cash_clearing`

Финальная схема должна быть единообразной для всех refund flows.

### Case 4. Bonus accrual

Пример:
- debit `bonus_expense`
- credit `bonus_liability`

### Case 5. Bonus redemption

Пример:
- debit `bonus_liability`
- credit `customer_receivable`

## Idempotency Model

### Client-side idempotency

Каждая команда изменения состояния должна иметь `idempotency_key`.

Формат:
- UUIDv7 или эквивалентный globally unique key;
- уникальность в пределах tenant plus operation scope;
- хранение результата первой обработки.

Уровень хранения:
- отдельная таблица `idempotency_records`;
- уникальный индекс по:
  - `tenant_id`
  - `operation_name`
  - `idempotency_key`

Хранимое содержимое:
- request hash
- response snapshot
- processing status
- resource type
- resource id
- created_at
- expires_at

Повтор с тем же ключом и тем же payload:
- возвращает тот же результат.

Повтор с тем же ключом и другим payload:
- отклоняется как misuse.

### Provider-side idempotency

Внешние запросы к провайдеру, создающие или меняющие деньги, должны отправляться с provider-supported idempotency semantics.

Для Stripe это соответствует использованию `Idempotency-Key` для безопасного повторения mutating requests.

## Webhook Processing Model

### Requirements

Webhook handler обязан:
- валидировать подпись;
- сохранять raw payload и headers;
- обеспечивать deduplication;
- быть быстрым и минимально stateful;
- не выполнять тяжёлую бизнес-логику синхронно в HTTP request path.

### Pipeline

#### Step 1. Receive
Принимаем webhook request.

#### Step 2. Verify
Проверяем подпись провайдера.

#### Step 3. Persist raw event
Сохраняем неизменённый payload.

#### Step 4. Deduplicate
Проверяем `provider_event_id` и при необходимости хеш содержимого.

#### Step 5. Enqueue
Отправляем в асинхронную обработку.

#### Step 6. Process
Выполняем domain mapping и ledger posting.

#### Step 7. Mark final state
Отмечаем `processed`, `failed_retryable` или `failed_terminal`.

### Duplicate handling

Один и тот же webhook event может приходить повторно. Это ожидаемое поведение, а не аномалия. Поэтому уникальность должна обеспечиваться на уровне хранилища и обработчика.

### Out-of-order handling

События могут приходить не в том порядке, в котором они были созданы. Поэтому processor обязан:
- проверять текущий aggregate state;
- уметь быть no-op для уже применённого результата;
- переводить событие в reconciliation queue, если ему не хватает контекста.

## Reconciliation

Reconciliation обязателен, даже при использовании webhook-driven architecture.

### Objectives

- выявлять payment objects без подтверждённого ledger posting;
- находить ledger-posted объекты без ожидаемого provider-side финального статуса;
- находить refund gaps;
- находить зависшие `payment_attempts`;
- выявлять расхождения сумм.

### Sources

- внутренние payment aggregates;
- ledger entries;
- provider events;
- provider polling API;
- audit logs.

### Reconciliation modes

1. Near-real-time
   Лёгкие фоновые проверки каждые несколько минут.

2. Daily finance reconciliation
   Полная сверка за период.

3. Incident recovery mode
   Принудительный replay или targeted repair по `payment_id`, `booking_id`, `provider_event_id`.

## Persistence and Constraints

Рекомендуемые таблицы:
- `payments`
- `payment_attempts`
- `refunds`
- `provider_events`
- `ledger_accounts`
- `ledger_entries`
- `ledger_postings`
- `idempotency_records`
- `payment_reconciliations`
- `payment_audit_log`

Рекомендуемые ограничения:
- unique:
  - `payments.provider + payments.provider_payment_ref`, если reference nullable-safe и уникален;
  - `provider_events.provider + provider_events.provider_event_id`;
  - `idempotency_records.tenant_id + operation_name + idempotency_key`;
- check:
  - `amount_total >= 0`
  - `amount_captured >= 0`
  - `amount_refunded >= 0`
  - `amount_captured <= amount_total`
  - `amount_refunded <= amount_captured`
- foreign keys:
  - строго по tenant-safe модели;
- application rule:
  - ledger entries и postings после posting не update и не delete.

## Transaction Boundaries

### Principle

Domain mutation и ledger posting должны выполняться в одной локальной транзакции базы данных, когда это касается внутреннего состояния.

### Recommended database behavior

- default isolation может оставаться `READ COMMITTED` для большинства сценариев;
- для критичных конкурентных участков применяются:
  - `SELECT ... FOR UPDATE`
  - unique constraints
  - retry on serialization or unique violations
  - transactional outbox pattern для внешних side effects.

### Commands requiring stronger concurrency control

- create payment by booking when duplicate submission possible;
- refund creation;
- bonus redemption;
- admin correction postings;
- reconciliation repair commands.

## Outbox and Eventing

Любые внешние side effects после коммита локальной транзакции должны публиковаться через transactional outbox.

Примеры:
- отправка уведомления клиенту;
- публикация доменного события `payment_captured`;
- запуск loyalty accrual processor;
- аналитические события.

Это нужно, чтобы не возникало состояния:
- транзакция в БД закоммичена,
- а событие наружу потеряно.

## API Contract

### Public API principles

- клиент не должен знать внутренние ledger details;
- клиент получает бизнес-понятные ресурсы;
- сервер возвращает устойчивые machine-readable ошибки;
- mutating endpoints требуют `Idempotency-Key`.

### Example endpoints

- `POST /api/v1/payments`
- `GET /api/v1/payments/{payment_id}`
- `POST /api/v1/payments/{payment_id}/capture`
- `POST /api/v1/payments/{payment_id}/cancel`
- `POST /api/v1/payments/{payment_id}/refunds`
- `GET /api/v1/payments/{payment_id}/refunds`
- `POST /api/v1/webhooks/providers/stripe`

### Error format

Для HTTP error payload применяется формат problem details.

Минимальные поля:
- `type`
- `title`
- `status`
- `detail`
- `instance`

Дополнительные поля:
- `code`
- `correlation_id`
- `idempotency_key`
- `retryable`

## Security

### Mandatory controls

- проверка webhook signatures;
- secret rotation для provider credentials;
- запрет логирования чувствительных секретов;
- role-based access для refund и admin adjustments;
- полный audit trail для финансовых команд;
- tenant boundary enforcement;
- rate limit и anti-abuse для public payment endpoints;
- masking provider payload fragments в логах при необходимости.

### Explicit non-goals at this ADR level

Этот документ не описывает полную PCI compliance программу. Он фиксирует архитектурный контур приложения и доменные правила.

## Auditability

Каждое финансовое действие должно быть объяснимо.

Минимум, который обязан фиксироваться:
- кто инициировал команду;
- когда она была инициирована;
- какая причина указана;
- какой request payload был получен;
- какой provider response был получен;
- какие domain transitions произошли;
- какие ledger entries были созданы;
- какой `correlation_id` связал все этапы.

## Observability

### Required telemetry

Метрики:
- payment create success rate
- payment capture success rate
- refund success rate
- webhook verification failures
- duplicate webhook count
- reconciliation mismatches
- mean webhook processing latency
- stuck payment attempts
- stuck reconciliation jobs

Логи:
- structured logs only;
- обязательные поля:
  - `tenant_id`
  - `payment_id`
  - `refund_id`
  - `booking_id`
  - `provider`
  - `provider_event_id`
  - `correlation_id`
  - `idempotency_key`

Трейсинг:
- payment command -> provider call -> webhook receive -> processor -> ledger posting -> outbox publish

## Failure Handling

### Retryable failures

Примеры:
- temporary provider outage;
- network timeout;
- deadlock;
- serialization failure;
- transient DB connectivity issue.

Подход:
- bounded retries;
- exponential backoff;
- сохранение причин в `payment_attempts` и job metadata.

### Terminal failures

Примеры:
- invalid refund amount;
- refund over captured amount;
- broken tenant ownership;
- invalid provider signature;
- schema-invalid event payload after validation.

Подход:
- немедленный отказ;
- запись в audit log;
- создание ops-visible incident when required.

## Administrative Corrections

Административные корректировки допустимы только через отдельный use case и только как compensating entries.

Требования:
- обязательный `reason_code`;
- обязательный `comment`;
- обязательный `actor_id`;
- запрет на silent mutation existing entry;
- отдельная роль доступа;
- обязательная видимость в audit and finance reports.

## Reporting Rules

Финансовая отчётность приложения должна строиться не из полей `status` и не из разрозненных таблиц, а из ledger entries и их агрегаций.

Примеры отчётов:
- captured payments by day;
- refunds by period;
- deferred revenue snapshot;
- bonus liability snapshot;
- booking settlement status;
- unreconciled payment anomalies.

## Testing Strategy

### Unit tests

Покрыть:
- payment state machine;
- refund invariants;
- ledger balancing;
- idempotency record behavior;
- webhook dedup logic;
- reconciliation decision rules.

### Integration tests

Покрыть:
- DB transaction boundaries;
- concurrent refund attempts;
- duplicate create payment requests;
- webhook replay;
- out-of-order events;
- transactional outbox.

### Contract tests

Покрыть:
- provider adapter serialization;
- webhook payload parsing;
- signature verification;
- error mapping from provider to domain.

### Property tests

Желательны для:
- ledger balancing;
- amount arithmetic;
- invariants under random command sequences.

## Migration Plan

### Phase 1
Ввести payment aggregate, provider adapter interface, idempotency records и webhook raw store.

### Phase 2
Ввести внутренний ledger и posting engine.

### Phase 3
Перевести refund, bonuses и admin adjustments на ledger-first подход.

### Phase 4
Ввести reconciliation jobs и finance anomaly dashboard.

### Phase 5
Добавить второй provider adapter при необходимости.

## Consequences

### Positive

- устраняется риск скрытого двойного списания из-за повторов;
- все денежные изменения становятся объяснимыми;
- система становится устойчивее к duplicate и delayed webhooks;
- упрощается аудит;
- упрощается последующее масштабирование под несколько провайдеров;
- повышается качество финансовой аналитики и расследований инцидентов.

### Negative

- возрастает сложность модели;
- требуется дисциплина в posting rules;
- возрастает объём таблиц и событий;
- reconciliation становится обязательной частью платформы, а не опцией.

## Rejected Alternatives

### Alternative 1
Хранить только provider status без внутреннего ledger.

Причина отказа:
- невозможно надёжно объяснить внутреннее финансовое состояние;
- трудно строить бонусные и корректировочные сценарии;
- плохо масштабируется на multi-provider model.

### Alternative 2
Обновлять денежные остатки inplace без истории проводок.

Причина отказа:
- теряется объяснимость;
- усложняется расследование;
- возрастает риск silent corruption.

### Alternative 3
Обрабатывать webhook полностью синхронно в HTTP handler.

Причина отказа:
- хуже устойчивость;
- выше риск таймаутов;
- сложнее управлять retry и replay.

## Implementation Notes

Рекомендуемые application модули:
- `payments/domain/`
- `payments/application/`
- `payments/infrastructure/providers/`
- `payments/infrastructure/webhooks/`
- `payments/infrastructure/reconciliation/`
- `payments/infrastructure/outbox/`
- `ledger/domain/`
- `ledger/application/`
- `ledger/infrastructure/`

Рекомендуемые ключевые интерфейсы:
- `PaymentProviderPort`
- `WebhookVerifierPort`
- `LedgerPostingService`
- `IdempotencyService`
- `PaymentReconciliationService`

## Final Rule Set

Обязательные правила проекта:
1. Никаких destructive updates финансовой истории.
2. Никаких mutating commands без idempotency key.
3. Никаких прямых бизнес-изменений из webhook HTTP handler.
4. Никаких refund операций сверх captured amount.
5. Никаких silent admin corrections.
6. Никаких payment reports без опоры на ledger.
7. Никаких multi-tenant shortcut queries без tenant predicate.
8. Никаких raw provider secrets в логах.
9. Никаких side effects вне outbox после локального коммита.
10. Никаких обходов reconciliation для production.

## References

Ниже перечислены внешние источники, на которые опираются архитектурные решения и термины этого ADR.

1. Stripe API Reference, Idempotent requests
   https://docs.stripe.com/api/idempotent_requests

2. Stripe Docs, Advanced error handling
   https://docs.stripe.com/error-low-level

3. Stripe Docs, Webhooks
   https://docs.stripe.com/webhooks

4. Stripe Docs, Handle payment events with webhooks
   https://docs.stripe.com/webhooks/handling-payment-events

5. Stripe Docs, Process undelivered webhook events
   https://docs.stripe.com/webhooks/process-undelivered-events

6. Stripe Docs, Handle webhook versioning
   https://docs.stripe.com/webhooks/versioning

7. PostgreSQL Documentation, Transaction Isolation
   https://www.postgresql.org/docs/current/transaction-iso.html

8. PostgreSQL Documentation, SET TRANSACTION
   https://www.postgresql.org/docs/current/sql-set-transaction.html

9. RFC 9457, Problem Details for HTTP APIs
   https://www.rfc-editor.org/rfc/rfc9457.html

## Source Notes

Подтверждаемые внешними источниками тезисы, заложенные в этот ADR:
- идемпотентные ключи нужны для безопасного повтора mutating requests у Stripe;
- webhook-события могут переотправляться и должны обрабатываться идемпотентно;
- подпись webhook должна проверяться;
- в PostgreSQL по умолчанию используется `READ COMMITTED`;
- для HTTP API допустимо использовать формат problem details из RFC 9457.

Внутренние тезисы этого документа:
- выбор append-only ledger;
- состав агрегатов;
- схема posting rules;
- способ tenant partitioning;
- набор account codes;
- стратегия reconciliation;
- конкретный модульный layout проекта.

Эти пункты являются архитектурными решениями Reva Studio, а не внешними фактами.