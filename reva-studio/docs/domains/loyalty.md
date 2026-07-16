# Loyalty Domain

Status: Draft for implementation
Owner: Reva Studio Core Team
Bounded Context: Loyalty
Primary Goal: управлять бонусной системой клиента в рамках multi-tenant платформы Reva Studio
Last Updated: 2026-03-23

## 1. Purpose

Данный документ фиксирует предметную область loyalty-модуля Reva Studio как отдельный bounded context.
Документ является внутренней доменной спецификацией проекта и описывает целевую модель, бизнес-правила, ограничения, события и контракты модуля лояльности.

Loyalty-контекст отвечает за:

- начисление бонусов клиентам
- списание бонусов при оплате
- хранение неизменяемой истории операций
- управление сроком жизни бонусов
- расчёт баланса, доступного к использованию
- поддержку персональных и сегментных правил лояльности
- защиту от двойного начисления и повторного списания
- аудит и трассируемость всех изменений

Loyalty-контекст не отвечает за:

- эквайринг и фактическое проведение платежа
- бухгалтерский учёт
- CRM-коммуникации как отдельный процесс
- расписание мастеров и управление слотами
- управление каталогом услуг вне ссылок на него
- внешние маркетинговые кампании как самостоятельный bounded context

## 2. Domain Vision

Система лояльности должна быть:

- tenant-aware
- клиенто-центричной
- финансово-предсказуемой
- аудируемой
- идемпотентной на уровне бизнес-операций
- устойчивой к повторной доставке событий и повторным командам
- пригодной для аналитики, антифрода и роста до marketplace/SaaS-модели

Ключевая бизнес-идея:
каждый клиент имеет loyalty-account внутри конкретного tenant, а любые изменения бонусного баланса выражаются только через неизменяемые записи в журнале операций.

## 3. Ubiquitous Language

### 3.1 Core Terms

**Tenant**  
Отдельный бизнес-клиент платформы Reva Studio. Например, конкретная студия или салон.

**Client**  
Конечный клиент салона, который получает и использует бонусы.

**Loyalty Account**  
Доменный счёт клиента внутри tenant, через который рассчитывается бонусный баланс.

**Bonus Points**  
Внутренняя единица ценности программы лояльности. Не является деньгами, не подлежит выводу и существует только внутри бизнес-правил платформы.

**Ledger Entry**  
Неизменяемая запись в журнале loyalty-операций. Единственный допустимый способ изменить состояние баланса.

**Available Balance**  
Количество бонусов, доступных к использованию в текущий момент.

**Pending Balance**  
Количество бонусов, начисленных, но ещё не ставших доступными к использованию, если используется отложенная активация.

**Reserved Balance**  
Количество бонусов, временно заблокированных под будущую операцию списания.

**Expired Balance**  
Количество бонусов, утративших силу по сроку действия.

**Rule Set**  
Версионируемый набор бизнес-правил начисления, списания, ограничений и срока жизни бонусов.

**Accrual**  
Начисление бонусов клиенту.

**Redemption**  
Списание бонусов клиентом в счёт покупки.

**Reversal**  
Компенсирующая операция, отменяющая ранее выполненную доменную операцию без удаления истории.

**Expiration**  
Погашение бонусов по истечении срока действия.

**Tier**  
Уровень лояльности клиента, влияющий на коэффициенты начисления или доступные привилегии.

**Promotion**  
Временное правило или акция, изменяющая стандартную механику начисления или списания.

**Idempotency Key**  
Бизнес-ключ уникальности команды, защищающий от повторного выполнения одной и той же операции.

**Source Document**  
Первичный бизнес-объект, на основании которого произошла loyalty-операция. Например: completed booking, paid invoice, promo grant, manual adjustment.

## 4. Strategic Positioning

Loyalty — отдельный bounded context, который интегрируется с:

- Clients
- Bookings
- Payments
- Promotions
- Notifications
- Analytics
- Admin

Loyalty не должен напрямую зависеть от UI, Telegram Bot, CRM-экрана или платёжного провайдера.
Все внешние процессы взаимодействуют с ним через команды, события и контракты приложенческого слоя.

## 5. Domain Goals

1. Начислять бонусы строго по утверждённым правилам.
2. Исключать двойное начисление за один и тот же источник.
3. Исключать перерасход баланса.
4. Поддерживать частичное и полное списание.
5. Поддерживать компенсации без удаления истории.
6. Разделять начисленные, активные, зарезервированные и просроченные бонусы.
7. Давать полную трассируемость любого движения баланса.
8. Поддерживать многотенантность без утечки данных между tenant.
9. Поддерживать развитие до персональных правил, VIP-tier и сегментной лояльности.
10. Давать прозрачную базу для финансовой аналитики и маркетинга.

## 6. Domain Constraints

### 6.1 Tenant Isolation

- Loyalty Account существует только внутри одного tenant.
- Один и тот же client_id в разных tenant не означает общий баланс.
- Любой запрос к loyalty-данным обязан содержать tenant_id.
- Перенос бонусов между tenant запрещён по умолчанию.

### 6.2 Immutability

- История операций не редактируется и не удаляется.
- Исправления выполняются только компенсирующими записями.
- Итоговое состояние рассчитывается из журнала операций и подтверждённых производных проекций.

### 6.3 Monetary Safety

- Бонусы не хранятся в float.
- Для доменной модели используется целочисленная минимальная единица программы.
- Конвертация бонусов в денежную скидку определяется rule set и фиксируется в момент операции списания.

### 6.4 Business Idempotency

- Повторная команда с тем же idempotency_key не должна создавать новую операцию.
- Уникальность должна контролироваться минимум в разрезе tenant_id + operation_type + idempotency_key.

### 6.5 Balance Safety

- Available Balance не может стать отрицательным.
- Reserved Balance не может превышать Available Balance на момент резервирования.
- Redemption не может быть подтверждён без достаточного доступного остатка.

### 6.6 Traceability

Каждая операция обязана содержать:

- tenant_id
- loyalty_account_id
- operation_id
- operation_type
- source_type
- source_id
- rule_set_version
- actor_type
- actor_id
- created_at
- correlation_id
- causation_id при наличии

## 7. Business Principles

1. Лояльность принадлежит клиенту, но управляется правилами tenant.
2. Баланс — это производное состояние, а не первичная истина.
3. Истина хранится в ledger entries.
4. Начисление и списание — это доменные операции, а не UI-действия.
5. Любая ручная корректировка должна быть аудируема.
6. Срок действия бонусов должен быть прозрачен.
7. Маркетинговая гибкость не должна ломать финансовую предсказуемость.
8. При конфликте между удобством и консистентностью приоритет у консистентности.

## 8. Aggregates

## 8.1 LoyaltyAccount Aggregate

### Назначение

Главный агрегат, представляющий состояние бонусного счёта клиента внутри tenant.

### Identity

- loyalty_account_id
- tenant_id
- client_id

### State

- status
- tier_code
- currency_code
- available_balance
- pending_balance
- reserved_balance
- expired_balance_total
- lifetime_accrued
- lifetime_redeemed
- lifetime_expired
- current_rule_set_id
- current_rule_set_version
- opened_at
- closed_at
- last_activity_at

### Statuses

- active
- blocked
- archived
- closed

### Responsibilities

- принимать команды начисления
- принимать команды резервирования
- принимать команды подтверждения списания
- принимать команды отмены списания
- принимать команды компенсации
- применять доменные инварианты
- публиковать доменные события

### Invariants

- account должен принадлежать ровно одному tenant
- status=closed запрещает новые операции, кроме системных компенсаций
- available_balance >= 0
- pending_balance >= 0
- reserved_balance >= 0
- balances не изменяются напрямую, только через ledger

## 8.2 LoyaltyLedgerEntry Aggregate Root Alternative

В реализации допускается хранение Ledger Entry не как самостоятельного aggregate root, а как доменно-значимого immutable record, создаваемого в рамках транзакции LoyaltyAccount.

### Ledger Entry Fields

- ledger_entry_id
- tenant_id
- loyalty_account_id
- entry_type
- direction
- points
- money_equivalent_minor
- status
- source_type
- source_id
- source_line_id
- idempotency_key
- rule_set_id
- rule_set_version
- expires_at
- available_from
- reserved_until
- actor_type
- actor_id
- reason_code
- comment
- metadata
- correlation_id
- causation_id
- created_at

### Entry Types

- accrual
- accrual_reversal
- redemption_reserve
- redemption_confirm
- redemption_release
- redemption_reversal
- expiration
- manual_adjustment_credit
- manual_adjustment_debit
- migration_credit
- migration_debit
- tier_bonus
- promo_bonus

### Entry Statuses

- pending
- active
- reserved
- consumed
- expired
- reversed
- cancelled

## 8.3 LoyaltyRuleSet Aggregate

### Назначение

Версионируемый источник бизнес-правил loyalty-механики внутри tenant.

### Fields

- loyalty_rule_set_id
- tenant_id
- version
- status
- effective_from
- effective_to
- accrual_strategy
- redemption_strategy
- expiration_policy
- rounding_policy
- tier_matrix
- promo_stack_policy
- manual_adjustment_policy
- anti_fraud_policy
- created_by
- created_at
- published_at

### Statuses

- draft
- published
- deprecated
- archived

### Invariants

- одновременно может действовать только один published rule set на tenant для одного доменного канала, если политика не допускает параллельность
- опубликованная версия неизменяема
- изменение правил создаёт новую версию, а не редактирует старую

## 8.4 RewardOffer Aggregate

Опциональный агрегат для управляемых вознаграждений.

### Examples

- списать 500 бонусов за скидку 500 рублей
- списать 1000 бонусов за бесплатную услугу категории
- персональное предложение для VIP-tier

### Fields

- reward_offer_id
- tenant_id
- code
- name
- status
- redemption_cost_points
- redemption_value_type
- redemption_value
- start_at
- end_at
- per_client_limit
- global_limit
- segment_filter
- stack_policy
- metadata

## 8.5 LoyaltyTierSnapshot

Может быть отдельным агрегатом или частью LoyaltyAccount, если уровни меняются редко.

### Fields

- tier_code
- valid_from
- valid_to
- entry_threshold
- retention_policy
- benefits_snapshot

## 9. Value Objects

## 9.1 Points

- целое число
- не может быть дробным
- не может быть меньше нуля в контексте amount, но может быть представлен знаком через direction

## 9.2 MoneyMinor

- денежная сумма в минимальных единицах валюты
- используется для фиксирования денежного эквивалента в момент операции

## 9.3 RuleVersion

- pair: rule_set_id + version

## 9.4 OperationReference

- source_type
- source_id
- source_line_id optional

## 9.5 ExpirationPolicy

- none
- fixed_days_from_activation
- fixed_date
- end_of_month
- end_of_year
- rolling_window

## 9.6 RedemptionPolicy

- allow_partial
- allow_full_only
- min_points_per_redemption
- max_points_per_order
- max_discount_percent
- forbidden_service_categories
- eligible_payment_methods

## 9.7 Actor

- system
- admin
- staff
- client
- migration

## 10. Core Commands

## 10.1 OpenLoyaltyAccount

Создаёт loyalty account для клиента в рамках tenant.

### Preconditions

- account для tenant_id + client_id ещё не существует
- client принадлежит tenant

### Postconditions

- создан active account
- опубликовано событие LoyaltyAccountOpened

## 10.2 AccruePoints

Начисляет бонусы по source document или promo trigger.

### Input

- tenant_id
- client_id or loyalty_account_id
- points
- source_type
- source_id
- rule_version
- idempotency_key
- expires_at optional
- available_from optional

### Preconditions

- account active
- source документ допустим для начисления
- по заданному источнику не было уже успешного начисления, если повтор запрещён
- points > 0

### Postconditions

- создан ledger entry accrual
- баланс обновлён согласно status записи
- опубликовано PointsAccrued

## 10.3 ReservePointsForRedemption

Резервирует бонусы до подтверждения списания.

### Preconditions

- account active
- available_balance достаточен
- операция соответствует redemption policy

### Postconditions

- created redemption_reserve entry
- available_balance уменьшается
- reserved_balance увеличивается
- опубликовано PointsReservedForRedemption

## 10.4 ConfirmRedemption

Подтверждает окончательное списание зарезервированных бонусов.

### Preconditions

- существует активный reserve
- reservation не истекла
- сумма подтверждения не превышает reserve

### Postconditions

- reserve переводится в consumed через confirm entry
- reserved_balance уменьшается
- lifetime_redeemed увеличивается
- опубликовано RedemptionConfirmed

## 10.5 ReleaseReservedPoints

Освобождает резерв, если заказ отменён или не завершён.

### Preconditions

- существует active reserve

### Postconditions

- reserved_balance уменьшается
- available_balance восстанавливается
- опубликовано ReservedPointsReleased

## 10.6 ReverseOperation

Компенсирует ранее проведённую операцию.

### Preconditions

- операция существует
- операция допустима к компенсации
- не была полностью компенсирована ранее

### Postconditions

- создаётся compensating ledger entry
- история сохраняется
- опубликовано LoyaltyOperationReversed

## 10.7 ExpirePoints

Гасит просроченные бонусы.

### Preconditions

- наступил момент expiration
- points ещё не consumed, reversed или expired

### Postconditions

- создаётся expiration entry
- available_balance или pending_balance уменьшается
- lifetime_expired увеличивается
- опубликовано PointsExpired

## 10.8 ManualAdjustBalance

Ручная корректировка администратором.

### Preconditions

- actor имеет специальное право
- заполнен reason_code
- заполнен audit comment
- указан idempotency_key

### Postconditions

- создаётся manual_adjustment_credit или manual_adjustment_debit
- опубликовано BalanceAdjustedManually

## 11. Domain Events

## 11.1 Account Lifecycle

- LoyaltyAccountOpened
- LoyaltyAccountBlocked
- LoyaltyAccountUnblocked
- LoyaltyAccountClosed
- LoyaltyTierChanged

## 11.2 Balance Events

- PointsAccrued
- PointsActivated
- PointsReservedForRedemption
- RedemptionConfirmed
- ReservedPointsReleased
- PointsExpired
- BalanceAdjustedManually
- LoyaltyOperationReversed

## 11.3 Rules Events

- LoyaltyRuleSetPublished
- LoyaltyRuleSetDeprecated
- RewardOfferActivated
- RewardOfferExpired

## 11.4 Event Envelope Requirements

Каждое событие должно содержать:

- event_id
- event_type
- aggregate_id
- aggregate_type
- tenant_id
- occurred_at
- version
- correlation_id
- causation_id
- payload

## 12. Invariants

## 12.1 Financial Invariants

1. Нельзя списать больше доступного остатка.
2. Нельзя подтвердить списание без резерва, если используется двухшаговая схема.
3. Нельзя допустить двойное начисление по одному и тому же source document, если правило это запрещает.
4. Компенсация не удаляет исходную запись.
5. Итоговый баланс всегда вычислим из ledger.

## 12.2 Security Invariants

1. Tenant isolation обязателен в каждом запросе.
2. Manual adjustment требует повышенных прав.
3. Любое ручное действие оставляет audit trail.
4. Массовое начисление должно быть трассируемым до конкретного campaign или import batch.

## 12.3 Consistency Invariants

1. Rule set version фиксируется в записи операции и не должен переопределяться задним числом.
2. Expiration рассчитывается по той версии правила, которая действовала в момент начисления.
3. Денежный эквивалент redemption фиксируется в момент подтверждения списания.
4. Смена tier не должна ретроактивно менять уже записанные операции.

## 13. Balance Model

Рекомендуемая формула:

```text
available_balance =
  sum(active accrual credits)
- sum(consumed redemptions)
- sum(active manual debits)
- sum(expired points)
- sum(active reserves)

pending_balance =
  sum(pending accruals)

reserved_balance =
  sum(active reserves not yet confirmed or released)


  Система должна хранить как минимум:

ledger как источник истины
materialized projection баланса для быстрых чтений
механизм реконcиляции между ledger и projection
14. Accrual Policies
14.1 Standard Accrual

Примеры допустимых правил:

фиксированный процент от суммы заказа
фиксированное количество бонусов за визит
начисление только на услуги определённых категорий
разные коэффициенты по tier
бонус за первую покупку
бонус за день рождения
бонус за выполнение campaign trigger
14.2 Accrual Calculation Inputs
booking total
paid amount
service category
staff
client tier
promotion
channel
date/time context
first visit flag
loyalty rule set version
14.3 Accrual Restrictions
начисление возможно только по завершённой и подтверждённо оплаченной операции, если tenant не включил иное правило
отменённая услуга не должна создавать итоговое начисление
частично оплаченные заказы обрабатываются по policy tenant
одно и то же основание не должно начислять бонусы дважды
15. Redemption Policies
15.1 Supported Redemption Modes
частичное списание
полное списание до лимита
фиксированные reward offers
списание только на определённые категории услуг
запрет на совмещение с акциями по policy
15.2 Restrictions
можно ограничить процент скидки на заказ
можно ограничить минимум заказа для списания
можно ограничить минимум бонусов в операции
можно запретить списание на already discounted items
можно ограничить доступность по tier или segment
15.3 Reservation Strategy

Для защиты от гонок и отмен рекомендуется двухшаговая модель:

reserve at checkout/confirmation
confirm on successful payment completion
release on cancellation/timeout/failure
16. Expiration Model
16.1 Expiration Principles
у начисления может быть собственный expires_at
если политика expiration отключена, expires_at = null
expiration применяется к неиспользованному остатку начисления
first-expiring-first-consumed является рекомендуемой стратегией списания
16.2 Recommended Consumption Policy

При списании должны потребляться бонусы с ближайшим сроком истечения.
Это снижает объём сгорания и делает модель более предсказуемой для клиента.

16.3 Expiration Job

Фоновый процесс обязан:

находить начисления, у которых истёк срок действия
исключать already consumed/reversed/expired units
формировать expiration entries
быть идемпотентным
вести audit batch metadata
17. Tier Model

Tier влияет на:

accrual multiplier
доступ к special reward offers
срок действия бонусов
привилегии и персональные механики
Example Tier Codes
base
silver
gold
platinum
vip

Tier не должен быть вычислён на лету без следа в истории.
Смена уровня должна фиксироваться отдельным событием и снапшотом.

18. Anti-Fraud and Abuse Prevention
18.1 Fraud Risks
повторное начисление по одному booking/invoice
ручные корректировки без основания
злоупотребление возвратами и компенсациями
попытка списания после отмены заказа
конкурентные списания в гонке запросов
массовое начисление по ошибочному import batch
18.2 Required Controls
idempotency_key на все изменяющие команды
уникальные ограничения на source-based accrual
role-based permission на manual adjustments
reason_code обязателен для ручных действий
correlation_id для batch/import операций
anomaly flags для подозрительных шаблонов
reconciliation jobs между ledger и read models
soft velocity rules на число ручных корректировок за период
mandatory approval flow для операций выше порога tenant policy
18.3 Suspicion Signals
несколько начислений по одному source_id
серия manual credits одним actor за короткое время
резкие скачки списаний после массовых корректировок
компенсации без видимой первичной причины
high-value adjustments вне рабочего времени по policy tenant
19. Audit Model

Каждая изменяющая операция должна быть пригодна для ответа на вопросы:

кто сделал действие
когда сделал действие
на основании чего сделал действие
по какой версии правила сделано действие
какой баланс был до и после
было ли действие автоматическим или ручным
связано ли действие с другой операцией
Mandatory Audit Fields
actor_type
actor_id
reason_code
comment for manual actions
source_type
source_id
correlation_id
created_at
rule_set_version
20. Permissions Model

Минимальные роли:

platform_admin
tenant_owner
tenant_manager
staff
finance_admin
support_agent
system
Access Principles
client-facing интерфейс может только просматривать баланс и историю, без прямого изменения
staff не должен выполнять ручные корректировки по умолчанию
manual debit/credit выше порога требует elevated permission
публикация rule set доступна ограниченному кругу ролей
21. Integration Contracts
21.1 From Bookings

Loyalty получает сигнал о завершённой услуге или заказе.

Required Fields
tenant_id
booking_id
client_id
services
order_total_minor
discount_total_minor
payment_status
completed_at
21.2 From Payments

Loyalty подтверждает redemption только после допустимого платёжного состояния по policy tenant.

Required Fields
payment_id
source_order_id
paid_amount_minor
payment_status
paid_at
21.3 To Notifications

Loyalty публикует события:

начислены бонусы
сгорают бонусы
изменился уровень
доступна новая награда
21.4 To Analytics

Loyalty отдаёт данные для метрик:

accrued points
redeemed points
expired points
outstanding liability proxy
redemption rate
tier distribution
promo efficiency
22. Multi-Tenant Rules
Все rule sets изолированы по tenant.
Все балансы изолированы по tenant.
Reward offers по умолчанию изолированы по tenant.
Кросс-tenant общая loyalty-программа возможна только как отдельное осознанное расширение и не входит в базовую модель.
Tenant не должен видеть ledger entries другого tenant ни при каких обстоятельствах.
23. Recommended Persistence Model

Это не жёсткая реализация, а рекомендуемая доменная форма хранения.

23.1 Tables or Collections
loyalty_accounts
loyalty_ledger_entries
loyalty_rule_sets
loyalty_reward_offers
loyalty_tier_snapshots
loyalty_balance_projections
loyalty_operation_links
loyalty_batches
loyalty_audit_log
23.2 Critical Indexes
unique tenant_id + client_id for active loyalty account
unique tenant_id + operation_type + idempotency_key
unique tenant_id + source_type + source_id + entry_type when required by policy
index on tenant_id + loyalty_account_id + created_at
index on tenant_id + expires_at for expiration jobs
index on tenant_id + status for projections and operations
24. Read Models

Для чтения допускаются отдельные projections:

24.1 ClientBalanceView
client current balance
pending
reserved
expiring soon
tier
last activity
24.2 LoyaltyHistoryView
chronological operations
readable labels
source references
before/after values if materialized
24.3 AdminRiskView
manual adjustments
reversals
unusual activity
near-expiration liabilities
24.4 CampaignEffectivenessView
accrual by promo
redemption by promo
active clients impacted
revenue influence proxy
25. Domain Policies
25.1 No Hard Delete Policy

Ни одна подтверждённая loyalty-операция не удаляется физически из предметной истории.

25.2 Compensation Instead of Mutation

Ошибка исправляется только обратной или компенсирующей операцией.

25.3 Rule Version Freeze Policy

Операция всегда несёт ссылку на ту версию правил, по которой она была создана.

25.4 Earliest Expiration First Policy

При списании по умолчанию сначала расходуются бонусы с ближайшим сроком истечения.

25.5 Restricted Manual Operations Policy

Ручные операции — исключение, а не норма.

26. Domain Scenarios
26.1 Standard Visit Accrual
Клиент завершил визит.
Платёж подтверждён.
Bookings/Payments публикуют факт завершения.
Loyalty вычисляет применимый rule set.
Система создаёт accrual entry.
Баланс клиента увеличивается.
Публикуется PointsAccrued.
26.2 Redemption During Checkout
Клиент хочет использовать бонусы.
Система рассчитывает максимально допустимое списание.
Выполняется reserve.
После успешной оплаты создаётся confirm.
При неуспехе оплаты выполняется release.
26.3 Order Cancellation After Accrual
По заказу ранее были начислены бонусы.
Заказ отменён или признан недействительным.
Loyalty создаёт accrual_reversal.
История сохраняет связь с первичным начислением.
26.4 Bonus Expiration
Ночной job находит истёкшие начисления.
Система создаёт expiration entries.
Баланс уменьшается.
Публикуется PointsExpired.
Notifications могут предупредить клиента заранее в другом процессе.
26.5 Manual Compensation By Manager
Менеджер обнаружил ошибку.
Создаёт manual adjustment с reason_code.
Система проверяет права и policy threshold.
Создаёт immutable ledger entry.
Операция отображается в audit и risk view.
27. Failure Handling
27.1 Duplicate Command

Если приходит команда с уже использованным idempotency_key, операция не должна повторяться.
Система должна вернуть уже известный результат или безопасный статус повторного запроса.

27.2 Insufficient Balance

Команда redemption должна завершаться доменной ошибкой insufficient_available_balance.

27.3 Rule Set Missing

Если нет действующего rule set и операция без него невозможна, команда отклоняется с domain error.

27.4 Tenant Mismatch

Любая попытка выполнить операцию с несоответствующим tenant_id должна отклоняться немедленно.

27.5 Reservation Timeout

Просроченный reserve должен быть released автоматикой или в момент проверки.

28. Domain Errors

Рекомендуемые domain error codes:

loyalty_account_not_found
loyalty_account_closed
loyalty_account_blocked
insufficient_available_balance
insufficient_reserved_balance
duplicate_business_operation
invalid_rule_set
reward_offer_not_available
redemption_not_allowed
points_already_expired
source_already_rewarded
tenant_mismatch
forbidden_manual_adjustment
reservation_expired
operation_already_reversed
invalid_operation_state
29. Observability Requirements

Loyalty-модуль обязан быть наблюдаемым на уровне доменных операций.

Must Have
structured logs per command
correlation_id across services
counters for accruals/redemptions/expirations/reversals
anomaly counters for manual adjustments
latency metrics by command type
dead-letter visibility for integration failures
reconciliation reports
30. Data Retention Principles
История loyalty-операций хранится дольше, чем UI-история клиента.
Архивация не должна ломать аудит и реконcиляцию.
Удаление или анонимизация персональных данных не должна уничтожать финансово-значимую доменную историю без предусмотренного механизма псевдонимизации.
31. Acceptance Criteria
31.1 Accrual
система может начислить бонусы по завершённой покупке
повторный вызов с тем же idempotency_key не создаёт второй записи
источник начисления можно проследить до source document
31.2 Redemption
нельзя списать больше available balance
reserve и confirm корректно меняют available и reserved
release полностью восстанавливает резерв
31.3 Expiration
просроченные бонусы гасятся автоматически
already consumed points не гасятся повторно
expiration audit сохраняется
31.4 Manual Adjustment
без прав операция запрещена
с правами операция требует reason_code
операция видна в audit view
31.5 Multi-Tenant
данные одного tenant не доступны другому
rule sets и balances изолированы
cross-tenant leakage исключён на уровне доменной модели и запросов
32. Implementation Notes
32.1 Recommended Architectural Shape
domain layer: aggregates, entities, value objects, domain services, policies
application layer: commands, handlers, transactions, idempotency orchestration
infrastructure layer: repositories, projections, message bus, scheduler
interface layer: admin API, bot API, internal events
32.2 Recommended Domain Services
loyalty_accrual_calculator
redemption_policy_service
expiration_planner
tier_evaluator
anti_fraud_evaluator
reconciliation_service
32.3 Recommended Repository Contracts
LoyaltyAccountRepository
LoyaltyLedgerRepository
LoyaltyRuleSetRepository
RewardOfferRepository
LoyaltyProjectionRepository
33. Future Extensions

Следующие расширения допускаются без ломки базовой модели:

referral loyalty
family/shared wallets
subscription-based loyalty
NFT/token-style bonus wrappers
coalition loyalty between multiple salons
AI-personalized reward generation
predictive churn incentives
dynamic tier engine
external partner redemptions

Эти расширения не входят в MVP, но текущая доменная модель должна не препятствовать их внедрению.

34. Final Domain Decision

Для Reva Studio loyalty должен строиться вокруг трёх опор:

Immutable ledger
Strict tenant isolation
Versioned business rules

Любая реализация, нарушающая хотя бы один из этих принципов, считается несоответствующей доменной модели.

35. Summary

Loyalty-контекст Reva Studio — это не просто поле bonus_balance, а отдельная доменная подсистема с собственными агрегатами, событиями, правилами, аудитом и anti-fraud механизмами.

Минимально корректная production-реализация обязана обеспечивать:

неизменяемую историю операций
защиту от дублей
безопасное списание через reserve/confirm
срок жизни бонусов
tenant isolation
audit trail
rule versioning

Без этих свойств loyalty-модуль будет хрупким, трудно проверяемым и рискованным для масштабирования SaaS-платформы.