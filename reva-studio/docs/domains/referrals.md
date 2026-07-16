# Referrals Domain

## Status

Approved

## Purpose

Домен `referrals` отвечает за реферальную механику Reva Studio.

Его задача:
- учитывать, кто и кого пригласил;
- фиксировать источник приглашения;
- предотвращать повторное и некорректное начисление;
- определять момент, когда приглашение считается успешным;
- инициировать выдачу бонуса, награды или иного вознаграждения;
- предоставлять прозрачную основу для аналитики, антифрода и аудита.

Домен не должен напрямую управлять балансами, платежами, промокодами или уведомлениями.
Он определяет правила реферального события и публикует доменные факты для других подсистем.

## Business Goal

Реферальная система нужна для:
- роста клиентской базы;
- увеличения доли органических рекомендаций;
- стимулирования возврата клиентов;
- создания прозрачной и контролируемой бонусной механики;
- поддержки индивидуальных бонусных программ для каждого клиента.

## Domain Boundaries

### In Scope

Домен `referrals` включает:
- создание и жизненный цикл реферальной кампании;
- генерацию и учёт реферальных кодов или ссылок;
- связывание пригласившего и приглашённого;
- валидацию условий успеха;
- защиту от повторного зачёта;
- фиксацию статуса начисления награды;
- публикацию доменных событий.

### Out of Scope

Вне домена:
- фактическое зачисление денег или токенов;
- ведение кошельков и балансов;
- обработка платежей;
- отправка push, Telegram или email-уведомлений;
- UI-отрисовка пользовательских экранов;
- маркетинговый copywriting;
- финальная antifraud-аналитика как отдельный сервис.

Эти задачи реализуются через другие домены или интеграции.

## Core Concepts

### Referrer

Пользователь, который приглашает другого пользователя или клиента в систему.

### Referred User

Пользователь, пришедший по приглашению.

### Referral Code

Уникальный код, который связывает приглашение с владельцем кода.

### Referral Link

Ссылка, содержащая код или иной идентификатор источника приглашения.

### Referral Attribution

Факт привязки приглашённого пользователя к пригласившему.

### Referral Conversion

Подтверждённое успешное выполнение условий программы.
Например:
- регистрация;
- подтверждение контакта;
- первый визит;
- первая оплаченная запись;
- достижение минимальной суммы заказа.

### Reward

Вознаграждение за успешное приглашение.
Награда может быть выражена:
- бонусами;
- скидкой;
- токенами;
- фиксированной суммой;
- процентом;
- сервисным преимуществом.

### Referral Campaign

Набор правил, определяющих:
- период действия;
- аудиторию;
- тип вознаграждения;
- условия квалификации;
- лимиты;
- ограничения;
- совместимость с другими механиками.

## Domain Model

### Aggregate: ReferralProgram

Корневой агрегат, описывающий правила реферальной программы.

#### Responsibilities
- хранить статус активности программы;
- определять допустимые условия участия;
- задавать правила квалификации;
- задавать тип и размер награды;
- ограничивать количество применений;
- определять сроки действия.

#### Key Fields
- `program_id`
- `code`
- `name`
- `description`
- `status`
- `starts_at`
- `ends_at`
- `reward_type`
- `reward_value`
- `qualification_rule`
- `max_rewards_per_referrer`
- `max_uses_total`
- `stacking_policy`
- `created_at`
- `updated_at`

### Aggregate: ReferralAttribution

Корневой агрегат факта приглашения.

#### Responsibilities
- связывать referrer и referred user;
- фиксировать источник атрибуции;
- защищать от повторной привязки;
- хранить статус конверсии;
- хранить статус награды;
- публиковать доменные события.

#### Key Fields
- `attribution_id`
- `program_id`
- `referrer_user_id`
- `referred_user_id`
- `referral_code`
- `source_channel`
- `status`
- `qualified_at`
- `reward_status`
- `reward_requested_at`
- `reward_confirmed_at`
- `rejection_reason`
- `created_at`
- `updated_at`

### Entity: ReferralRewardRequest

Сущность, описывающая запрос на выдачу награды во внешний домен.

#### Key Fields
- `reward_request_id`
- `attribution_id`
- `beneficiary_user_id`
- `reward_type`
- `reward_value`
- `status`
- `idempotency_key`
- `requested_at`
- `processed_at`
- `failure_reason`

## Ubiquitous Language

Во всех backend, product и аналитических документах использовать следующие термины:
- `referrer`
- `referred_user`
- `referral_code`
- `attribution`
- `conversion`
- `qualification`
- `reward`
- `campaign`
- `idempotency`
- `fraud_review`
- `reward_status`

Не использовать смешение терминов вроде:
- "партнёр" вместо `referrer`, если речь не о партнёрской программе;
- "купон" вместо `referral_code`, если это именно приглашение;
- "промокод" вместо `referral_code`, если код не даёт скидку сам по себе.

## State Model

### ReferralProgram Status
- `draft`
- `scheduled`
- `active`
- `paused`
- `expired`
- `archived`

### ReferralAttribution Status
- `pending`
- `qualified`
- `rejected`
- `expired`
- `cancelled`

### Reward Status
- `not_requested`
- `requested`
- `processing`
- `granted`
- `rejected`
- `reversed`

## Qualification Rules

Реферальная атрибуция может считаться успешной только после выполнения заранее определённого правила квалификации.

Поддерживаемые типы правил:
- `on_registration`
- `on_contact_verification`
- `on_first_booking_created`
- `on_first_booking_completed`
- `on_first_paid_booking`
- `on_threshold_spent`
- `custom_rule`

Для production-режима рекомендуется использовать не регистрацию, а бизнес-значимое действие.
Например:
- первый завершённый визит;
- первая оплаченная запись;
- достижение минимальной суммы.

Это снижает риск злоупотреблений и "пустых" регистраций.

## Invariants

Следующие инварианты должны соблюдаться всегда:

1. Один приглашённый пользователь не может быть навсегда атрибутирован более чем к одному referrer в рамках одной программы.

2. Пользователь не может пригласить сам себя.

3. Награда не может быть выдана без успешной квалификации.

4. Награда по одной и той же атрибуции не может быть выдана дважды.

5. Повторная обработка одного и того же события должна быть идемпотентной.

6. Если программа неактивна, новая атрибуция не создаётся.

7. Если срок действия программы истёк, квалификация по ней не подтверждается, если иное явно не разрешено правилами кампании.

8. Если пользователь уже существовал в системе до реферального клика или до допустимого окна атрибуции, правила допуска определяются программой и проверяются явно.

## Anti-Fraud Rules

Минимальный обязательный набор защит:
- запрет self-referral;
- запрет множественной награды за одну и ту же квалификацию;
- дедупликация по `referred_user_id`;
- дедупликация по idempotency key;
- журнал причин отказа;
- возможность ручной проверки спорных кейсов;
- флаг подозрительной активности;
- ограничение на количество наград за период;
- ограничение по устройству, контакту или иному сигналу, если такие данные разрешены политикой конфиденциальности.

Антифрод не должен silently отклонять событие без причины.
Любой отказ должен оставлять audit trail.

## Idempotency

Все операции выдачи награды и подтверждения квалификации должны быть идемпотентны.

### Required Idempotency Keys
- `qualification:{program_id}:{referred_user_id}`
- `reward:{attribution_id}:{beneficiary_user_id}:{reward_type}`

Повторная доставка одного и того же события не должна менять финальный результат второй раз.

## Domain Events

### ReferralAttributionCreated
Публикуется при успешном создании связи между referrer и referred user.

Payload:
- `attribution_id`
- `program_id`
- `referrer_user_id`
- `referred_user_id`
- `referral_code`
- `occurred_at`

### ReferralQualified
Публикуется, когда выполнены условия квалификации.

Payload:
- `attribution_id`
- `program_id`
- `referrer_user_id`
- `referred_user_id`
- `qualification_rule`
- `qualified_at`

### ReferralRewardRequested
Публикуется, когда домен `referrals` запросил выдачу награды.

Payload:
- `reward_request_id`
- `attribution_id`
- `beneficiary_user_id`
- `reward_type`
- `reward_value`
- `requested_at`

### ReferralRewardGranted
Публикуется после подтверждённой выдачи награды внешним доменом.

Payload:
- `reward_request_id`
- `attribution_id`
- `beneficiary_user_id`
- `granted_at`

### ReferralRejected
Публикуется при отклонении атрибуции или квалификации.

Payload:
- `attribution_id`
- `program_id`
- `reason_code`
- `occurred_at`

## Reason Codes

Рекомендуемый набор кодов отказа:
- `self_referral`
- `duplicate_attribution`
- `duplicate_reward`
- `program_inactive`
- `program_expired`
- `qualification_not_met`
- `fraud_suspected`
- `referred_user_ineligible`
- `referrer_ineligible`
- `manual_rejection`
- `technical_conflict`

## Read Models

Для приложения и аналитики домен должен предоставлять отдельные read model.

### Referrer Dashboard View
Поля:
- `user_id`
- `program_id`
- `total_invites`
- `qualified_invites`
- `pending_invites`
- `rejected_invites`
- `granted_rewards_total`
- `last_referral_at`

### Referral Attribution View
Поля:
- `attribution_id`
- `referrer_user_id`
- `referred_user_id`
- `program_id`
- `status`
- `reward_status`
- `created_at`
- `qualified_at`
- `rejection_reason`

### Campaign Performance View
Поля:
- `program_id`
- `program_name`
- `attributions_total`
- `qualified_total`
- `conversion_rate`
- `reward_cost_total`
- `avg_time_to_qualify`
- `rejection_rate`

## Permissions

Минимальные роли:
- `customer`
- `staff`
- `manager`
- `admin`
- `system`

### Access Rules
- `customer` может видеть только свои реферальные данные;
- `staff` не должен менять атрибуцию вручную без отдельного разрешения;
- `manager` может смотреть аналитику кампаний;
- `admin` может создавать, останавливать и архивировать программы;
- `system` может публиковать и обрабатывать интеграционные события.

## Integration Contracts

### Users Domain
Используется для:
- проверки существования пользователя;
- проверки, не является ли приглашённый тем же самым пользователем;
- чтения признаков допустимости участия.

### Bookings Domain
Используется для:
- подтверждения первого визита;
- подтверждения завершённой записи;
- получения суммы заказа, если правило зависит от порога.

### Payments Domain
Используется для:
- подтверждения факта оплаты;
- определения квалификации по оплаченной услуге;
- подтверждения суммы для threshold-based механик.

### Loyalty Domain
Используется для:
- выдачи бонусов;
- начисления внутренних баллов;
- реверса наград при отмене.

### Notifications Domain
Используется для:
- отправки уведомления referrer;
- отправки уведомления referred user;
- информирования о статусе награды.

### Audit Domain
Используется для:
- фиксации административных действий;
- хранения trail по отклонениям, реверсам и ручным решениям.

## Recommended API Surface

Ниже не контракт транспорта, а рекомендуемая функциональная поверхность.

### Customer Operations
- получить свой реферальный код;
- получить свою реферальную ссылку;
- посмотреть список приглашённых;
- посмотреть статус каждого приглашения;
- посмотреть историю наград.

### Admin Operations
- создать программу;
- активировать программу;
- приостановить программу;
- завершить программу;
- посмотреть метрики программы;
- вручную отклонить спорную атрибуцию;
- перевести кейс в fraud review;
- инициировать реверс награды через внешний домен.

## Data Retention

Реферальные события относятся к финансово и аналитически значимым.
Поэтому рекомендуется:
- не удалять атрибуции физически;
- использовать soft delete только там, где это не ломает аудит;
- хранить history изменения статусов;
- хранить причины отказов и реверсов;
- хранить idempotency keys и correlation ids.

## Observability

Для production обязательны:
- correlation id на все команды и события;
- audit log на административные действия;
- business metrics по конверсии;
- технические метрики по ошибкам интеграций;
- dead-letter обработка неуспешных событий;
- алерты на всплеск fraud_suspected и duplicate_reward.

### Key Metrics
- referrals_created_total
- referrals_qualified_total
- referrals_rejected_total
- referral_rewards_requested_total
- referral_rewards_granted_total
- referral_rewards_rejected_total
- referral_conversion_rate
- referral_reward_cost_total
- referral_duplicate_attempts_total
- referral_fraud_review_total

## Failure Scenarios

### Case 1: Reward service temporarily unavailable
Поведение:
- статус запроса награды переводится в `processing` или `requested`;
- событие остаётся доступным для retry;
- повтор не должен создавать вторую награду.

### Case 2: Booking cancelled after reward granted
Поведение:
- политика определяется кампанией;
- если предусмотрен clawback, публикуется событие реверса;
- сам реверс выполняется во внешнем домене наград или loyalty.

### Case 3: Duplicate delivery of qualification event
Поведение:
- повторная обработка безопасна;
- итоговая награда остаётся одной;
- инцидент фиксируется в observability.

## Example Business Flows

### Flow A: First paid booking
1. Referrer делится ссылкой.
2. Новый клиент переходит по ссылке и регистрируется.
3. Создаётся `ReferralAttribution` со статусом `pending`.
4. Клиент оформляет и оплачивает первую запись.
5. Домен `payments` или `bookings` публикует событие.
6. Домен `referrals` проверяет qualification rule.
7. Атрибуция переходит в `qualified`.
8. Создаётся `ReferralRewardRequest`.
9. Внешний домен подтверждает выдачу награды.
10. `reward_status` переходит в `granted`.

### Flow B: Invalid self-referral
1. Пользователь пытается использовать собственный код.
2. Проверка identity выявляет совпадение.
3. Атрибуция не квалифицируется.
4. Сохраняется причина `self_referral`.
5. Публикуется `ReferralRejected`.

## Open Design Decisions

Следующие решения должны быть закреплены отдельным ADR:
- считается ли успешной только оплаченная запись или завершённый визит;
- допускается ли награда обеим сторонам;
- можно ли суммировать реферальную награду с промокодами;
- какой срок жизни у реферальной атрибуции;
- допускается ли смена referrer до первой квалификации;
- как обрабатывать отмену и возврат после уже выданной награды;
- какие ограничения действуют для сотрудников студии;
- можно ли использовать реферальный код офлайн через администратора.

## Recommended ADR List

- ADR: Referral qualification strategy
- ADR: Reward issuing model
- ADR: Referral anti-fraud policy
- ADR: Stacking policy with discounts and promo codes
- ADR: Reversal and clawback policy
- ADR: Attribution window policy

## Minimal Acceptance Criteria

Домен считается готовым к production, если:
- нельзя выдать двойную награду;
- self-referral блокируется;
- есть audit trail;
- все статусы воспроизводимы и объяснимы;
- qualification проверяется детерминированно;
- retry безопасен;
- аналитика видит воронку от атрибуции до награды;
- административные действия журналируются;
- реверс поддерживается отдельной политикой.

## Summary

Домен `referrals` в Reva Studio должен быть не "таблицей с кодами", а полноценным доменным контуром с:
- ясной моделью атрибуции;
- проверяемыми правилами квалификации;
- идемпотентной выдачей наград;
- антифрод-защитой;
- audit trail;
- наблюдаемостью;
- чистыми интеграционными контрактами.

Именно такая модель позволяет масштабировать реферальную механику без хаоса, повторных начислений и потери управляемости.