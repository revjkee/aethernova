# Tenant Plans

Статус: Production Draft  
Контекст: Reva Studio  
Область: Product / Multi-tenant SaaS / Billing  
Последнее обновление: 2026-03-23

---

## 1. Назначение документа

Этот документ фиксирует промышленную модель тарифов, ограничений, entitlement-правил и tenant lifecycle для Reva Studio как multi-tenant SaaS-платформы для beauty-бизнеса.

Документ нужен для того, чтобы:

- единообразно описать планы арендаторов;
- отделить тариф от технической изоляции tenant;
- дать backend, billing, onboarding, CRM и analytics единый источник правил;
- исключить хаотичное добавление индивидуальных фич под каждого клиента;
- связать план, лимиты, feature flags, биллинг и эксплуатацию.

---

## 2. Внешняя проверяемая база

Ниже перечислено то, что является не внутренним мнением проекта, а опирается на официальные документы.

### 2.1 Что такое multitenancy

Microsoft определяет multitenancy как архитектурный подход, при котором компоненты разделяются между несколькими tenants, обычно соответствующими клиентам. При этом multitenancy не означает, что каждый компонент системы обязан быть shared.  
Источник:  
https://learn.microsoft.com/en-us/azure/architecture/guide/saas-multitenant-solution-architecture/

### 2.2 Почему tenant tier должен быть first-class сущностью

AWS SaaS Lens прямо указывает, что operations в multi-tenant SaaS должны смотреть на систему через призму tenants и tenant tiers, а onboarding должен включать создание tenant, администратора и конфигурацию billing plan или tier.  
Источник:  
https://docs.aws.amazon.com/wellarchitected/latest/saas-lens/operate.html

### 2.3 Почему нужно учитывать потребление по tenant

AWS отдельно указывает, что в multi-tenant среде нужна consumption mapping model, позволяющая атрибутировать потребление ресурсов по tenants. Это важно для себестоимости, лимитов и справедливого growth-монетизирования.  
Источник:  
https://docs.aws.amazon.com/wellarchitected/latest/saas-lens/expenditure-awareness.html

### 2.4 Какие модели подписки и usage common для SaaS

Stripe документирует, что subscriptions обычно поддерживают как минимум две модели usage-based billing: metered и per-seat licensing. Также Stripe отдельно документирует trials, prorations, flexible billing mode и mixed billing scenarios.  
Источники:  
https://docs.stripe.com/billing/subscriptions/quantities  
https://docs.stripe.com/billing/subscriptions/trials  
https://docs.stripe.com/billing/subscriptions/prorations  
https://docs.stripe.com/billing/subscriptions/billing-mode  
https://docs.stripe.com/billing/subscriptions/build-subscriptions

### 2.5 Что важно для pooled model

AWS указывает, что shared pool model даёт cost efficiency и agility, но увеличивает риск noisy neighbor и усложняет tenant isolation.  
Источник:  
https://docs.aws.amazon.com/wellarchitected/latest/saas-lens/pool-isolation.html

---

## 3. Что в этом документе является проектным решением

Ниже находятся внутренние решения Reva Studio. Это не цитаты из внешних стандартов, а целевая архитектура продукта.

К таким решениям относятся:

- названия тарифов;
- состав фич по каждому плану;
- лимиты по staff, branches, seats, messages и integrations;
- onboarding flow;
- upgrade/downgrade semantics;
- grace period;
- trial-политика;
- enterprise-исключения;
- tenant entitlement model.

Если бизнес позднее утвердит другие числа, этот документ должен обновляться через ADR или product policy change.

---

## 4. Базовые определения

### 4.1 Tenant

Tenant — это отдельный бизнес-клиент Reva Studio с собственной конфигурацией, пользователями, филиалами, мастерами, услугами, бронированиями, платёжными настройками, маркетинговыми настройками и доступом к фичам.

### 4.2 Tenant Plan

Tenant Plan — это коммерческий пакет продукта, который определяет:

- доступные возможности;
- количественные лимиты;
- модель биллинга;
- SLA и support-уровень;
- требования к изоляции и сопровождению.

### 4.3 Tenant Tier

Tenant Tier — это операционный и коммерческий уровень обслуживания tenant. Tier может совпадать с планом, но не обязан быть равен ему. Один и тот же plan может иметь разные support tier или migration tier.

### 4.4 Entitlement

Entitlement — это конкретное право tenant на использование возможности или ресурса. Например:

- право на 8 staff;
- право на 1 branch;
- право на Telegram Mini App;
- право на custom domain;
- право на advanced analytics.

### 4.5 Add-on

Add-on — это дополнительная платная возможность сверх базового плана. Add-on не должен ломать целостность базовой матрицы plans.

### 4.6 Seat

Seat — это оплачиваемое рабочее место пользователя back-office или сотрудника, который требует отдельного аккаунта в панели.

### 4.7 Metered Usage

Metered Usage — это тарифицируемое потребление, зависящее от фактического объёма, а не только от фиксированной подписки. Например:

- SMS;
- WhatsApp messages;
- AI tokens;
- outbound reminders;
- storage overage;
- API calls;
- advanced analytics jobs.

---

## 5. Продуктовые принципы тарифной системы

### 5.1 Один код, много tenants

Reva Studio строится как единая SaaS-платформа. Мы не делаем отдельную форк-версию продукта под каждого клиента. Кастомизация допускается через entitlement, flags, configuration и add-ons, но не через ручной fork приложения.

### 5.2 Plan должен быть machine-readable

Любой plan должен быть представлен не только в маркетинговом тексте, но и в виде нормализованных entitlement-правил в backend.

### 5.3 Цена отдельно, entitlement отдельно

Коммерческая цена может меняться чаще, чем техническая конфигурация. Поэтому:

- price catalog хранится отдельно;
- feature entitlements хранятся отдельно;
- tenant assignment к плану хранится отдельно.

### 5.4 Лимиты должны быть enforceable

Если лимит нельзя автоматически проверить, значит это плохой лимит. Например:

- лимит на branches можно проверить;
- лимит на active staff можно проверить;
- лимит на reminders можно проверить;
- лимит "умеренное использование" без метрики использовать нельзя.

### 5.5 Tier должен быть виден в observability

Поскольку tenant tier должен быть first-class сущностью в эксплуатации, любой event, metric, audit и support workflow должен содержать `tenant_id`, `plan_code` и `tier_code`.

### 5.6 Upgrade должен быть легче, чем downgrade

Система должна проектироваться так, чтобы апгрейд выполнялся быстро, прозрачно и без ручного вмешательства. Downgrade допускает отложенное применение и проверки на превышение лимитов.

---

## 6. Целевая линейка тарифов Reva Studio

Ниже предложена промышленная линейка для beauty SaaS. Это проектная модель.

### 6.1 Starter

Целевая аудитория:
- solo-master;
- micro-studio;
- один кабинет;
- ранний запуск.

Ключевая идея:
- низкий порог входа;
- закрытие базовых потребностей записи, клиентов и напоминаний;
- без тяжёлой аналитики и без мультифилиальности.

### 6.2 Growth

Целевая аудитория:
- студия с несколькими мастерами;
- одна основная локация;
- потребность в CRM, loyalty и отчётности;
- активное использование Telegram.

Ключевая идея:
- основной рабочий тариф для типового малого бизнеса.

### 6.3 Pro

Целевая аудитория:
- студия с несколькими направлениями услуг;
- 1-3 филиала;
- нужен более сильный контроль ролей, автоматизаций, аналитики и интеграций.

Ключевая идея:
- тариф для зрелого бизнеса, которому нужен не просто календарь, а управляемая операционная система.

### 6.4 Enterprise

Целевая аудитория:
- сеть студий;
- франшиза;
- кастомные интеграции;
- отдельные требования к SLA, миграции, security review, data handling и support.

Ключевая идея:
- договорной тариф с изолированными обязательствами и отдельным governance-процессом.

---

## 7. Рекомендуемая матрица plans

Ниже — проектная целевая матрица. Числа подлежат утверждению бизнесом.

```text
Plan: starter
- target: solo / micro
- branches_limit: 1
- active_staff_limit: 3
- seat_limit: 1
- services_limit: 50
- clients_limit: 3000
- monthly_booking_limit: unlimited
- reminder_messages_included: 1000
- ai_features: basic
- analytics: basic
- loyalty: no
- custom_branding: no
- custom_domain: no
- api_access: no
- integrations: basic
- support_tier: standard
- sla: best_effort
Plan: growth
- target: small studio
- branches_limit: 1
- active_staff_limit: 10
- seat_limit: 5
- services_limit: 200
- clients_limit: 20000
- monthly_booking_limit: unlimited
- reminder_messages_included: 5000
- ai_features: standard
- analytics: standard
- loyalty: yes
- custom_branding: limited
- custom_domain: no
- api_access: limited
- integrations: standard
- support_tier: priority_business_hours
- sla: standard
Plan: pro
- target: advanced studio
- branches_limit: 3
- active_staff_limit: 30
- seat_limit: 15
- services_limit: 1000
- clients_limit: 100000
- monthly_booking_limit: unlimited
- reminder_messages_included: 15000
- ai_features: advanced
- analytics: advanced
- loyalty: advanced
- custom_branding: yes
- custom_domain: yes
- api_access: yes
- integrations: advanced
- support_tier: priority
- sla: enhanced
Plan: enterprise
- target: chains / franchise / large operator
- branches_limit: custom
- active_staff_limit: custom
- seat_limit: custom
- services_limit: custom
- clients_limit: custom
- monthly_booking_limit: custom
- reminder_messages_included: custom
- ai_features: custom
- analytics: custom
- loyalty: custom
- custom_branding: yes
- custom_domain: yes
- api_access: yes
- integrations: custom
- support_tier: enterprise
- sla: contractual
8. Категории entitlement
8.1 Capacity entitlements

Это лимиты на объекты и объём:

branches_limit
active_staff_limit
seat_limit
services_limit
storage_gb_limit
api_requests_per_day_limit
reminder_messages_included
ai_credits_included
8.2 Feature entitlements

Это бинарные или параметризованные фичи:

booking_widget_enabled
telegram_bot_enabled
telegram_mini_app_enabled
loyalty_enabled
gift_cards_enabled
waitlist_enabled
deposit_payments_enabled
online_payments_enabled
reviews_enabled
marketing_campaigns_enabled
segmentation_enabled
analytics_advanced_enabled
custom_domain_enabled
white_label_enabled
api_access_enabled
webhooks_enabled
8.3 Governance entitlements
audit_log_retention_days
export_enabled
roles_count_limit
custom_roles_enabled
sso_enabled
security_review_required
data_residency_profile
8.4 Support entitlements
support_tier
onboarding_assistance
migration_assistance
training_sessions_included
account_manager_assigned
9. Какие лимиты должны быть soft, а какие hard
9.1 Hard limits

Это лимиты, которые система обязана enforce автоматически:

branches_limit
active_staff_limit
seat_limit
api_requests_limit
ai_credits_limit
storage_limit
reminder_messages_limit при поминутной или поштучной тарификации
9.2 Soft limits

Это лимиты, которые лучше предупреждать заранее, а не мгновенно блокировать:

clients_limit
services_limit
analytics retention
report exports
monthly campaign volume
9.3 Почему нужен mixed model

Полностью жёсткая модель повышает churn и support-load. Полностью мягкая модель ломает юнит-экономику. Поэтому в Reva Studio должна использоваться mixed enforcement policy:

warning at 80 percent;
warning at 95 percent;
grace window;
затем hard stop только для чётко тарифицируемых ресурсов.
10. Рекомендуемая биллинговая модель

Поскольку официальные биллинговые платформы поддерживают fixed subscription, per-seat и metered usage, Reva Studio должна использовать hybrid billing model.

10.1 Base subscription

Каждый tenant имеет базовую ежемесячную или ежегодную подписку по plan.

10.2 Seat-based billing

Seat-based billing используется для Growth, Pro и Enterprise, если tenant добавляет административных пользователей сверх включённого лимита.

10.3 Metered add-ons

Metered add-ons используются для:

SMS и мессенджинг;
AI usage;
storage overage;
premium reminder packs;
advanced exports;
external API volume.
10.4 Annual discount

Годовой тариф должен быть дешевле monthly в пересчёте на месяц, но entitlement остаются теми же, если специально не утверждено иное.

10.5 Proration policy

Так как prorations не применяются к usage-based billing на стороне Stripe, Reva Studio должна разделять:

proration для base subscription и seat changes;
non-prorated metered settlement для usage-потребления.
11. Рекомендуемые add-ons
Add-on: extra_staff_pack
- unit: 1 active staff
- applies_to: growth, pro, enterprise
- billing: monthly recurring

Add-on: branch_pack
- unit: 1 branch
- applies_to: pro, enterprise
- billing: monthly recurring

Add-on: sms_pack
- unit: message bucket
- applies_to: all plans
- billing: prepaid or metered

Add-on: ai_pack
- unit: AI credits
- applies_to: growth, pro, enterprise
- billing: prepaid or metered

Add-on: advanced_analytics
- unit: feature
- applies_to: growth, pro
- billing: recurring

Add-on: white_label
- unit: feature
- applies_to: pro, enterprise
- billing: recurring

Add-on: api_access
- unit: feature + request quota
- applies_to: pro, enterprise
- billing: recurring + optional metered overage

Правило:

add-on не должен полностью превращать Starter в Enterprise;
дорогие add-ons должны усиливать правильный план, а не обходить продуктовую лестницу.
12. Trial policy

Официальные биллинговые платформы поддерживают trial periods, в том числе совместно с usage-based billing. Это позволяет Reva Studio строить controlled trial without fake tenants.

Проектная политика:

12.1 Trial duration

Рекомендуемый trial:

7 дней для self-serve;
14 дней для acquisition campaigns;
custom для enterprise pilot.
12.2 Trial scope

В trial tenant получает:

полноценный onboarding;
базовый booking flow;
ограниченный messaging;
ограниченный import;
без destructive enterprise features.
12.3 Trial restrictions

Во время trial:

ограничить expensive AI;
ограничить bulk campaigns;
ограничить heavy exports;
ограничить white-label и custom domain;
ограничить интеграции, требующие ручного сопровождения.
12.4 Trial to paid conversion

При конверсии trial в paid:

tenant_id не меняется;
данные не мигрируются между разными сущностями;
entitlement переключаются атомарно;
historical events сохраняются.
13. Tenant lifecycle
13.1 Draft

Tenant создан, но не активирован.

13.2 Trialing

Tenant активен в trial-периоде.

13.3 Active

Tenant платит и имеет действующий plan.

13.4 Past Due

Есть проблема со списанием или счётом.

13.5 Grace

Tenant временно сохраняет доступ после проблемы с оплатой.

13.6 Suspended

Новые операции ограничены, критические функции заблокированы.

13.7 Churned

Tenant деактивирован как активный клиент.

13.8 Archived

Данные помещены в архив по retention policy.

14. Правила upgrade и downgrade
14.1 Upgrade

Upgrade должен:

применяться быстро;
включать entitlement немедленно;
вызывать proration только для recurring-компонентов;
не ломать существующие данные tenant.
14.2 Downgrade

Downgrade должен:

вступать в силу в конце billing period по умолчанию;
запускать pre-check на превышение лимитов;
формировать remediation tasks.
14.3 Downgrade blockers

Downgrade нельзя выполнить немедленно, если:

branches > new branches_limit;
active_staff > new staff_limit;
seats > new seat_limit;
используется feature, не поддерживаемая новым plan без safe fallback.
14.4 Downgrade remediation

Система должна уметь выдать чёткий список:

какие объекты превышают лимит;
что нужно отключить;
какие действия должен выполнить tenant-admin.
15. Что нельзя делать в планах
15.1 Нельзя кодировать права напрямую в if-else по plan name

Нужно использовать entitlement registry, а не логику вида:

if tenant.plan == "pro":
    ...
15.2 Нельзя смешивать billing state и access state

Потому что tenant может быть:

active, но с временным grace;
past_due, но ещё не suspended;
на старом plan, но с новым price;
на custom contract, но с планом Enterprise.
15.3 Нельзя форкать продукт ради одного tenant

Кастомизация должна идти через:

feature flags;
config;
add-ons;
tenant policy;
enterprise extension contracts.
15.4 Нельзя привязывать observability только к global метрикам

Поскольку AWS рекомендует tenant-aware operational views, все важные telemetry данные должны быть фильтруемы по:

tenant_id;
plan_code;
tier_code;
billing_status.
16. Модель tenant isolation по планам

Multitenancy не означает, что всё должно быть shared. Поэтому Reva Studio должна разделять billing plan и isolation profile.

16.1 Shared Pool Profile

Для Starter, Growth и части Pro:

shared application tier;
shared DB cluster;
logical isolation by tenant_id;
shared queue and cache namespaces with tenant-aware keys.
16.2 Enhanced Profile

Для части Pro:

stricter quotas;
dedicated rate limits;
optional dedicated storage bucket/path;
stronger audit retention;
higher observability priority.
16.3 Dedicated / Enterprise Profile

Для Enterprise:

optional dedicated DB;
optional dedicated Redis namespace or cluster;
optional dedicated worker pool;
optional custom domain stack;
contractual support and maintenance windows.

Важно:

plan не всегда равен isolation profile;
Enterprise по умолчанию допускает dedicated profile, но не обязан всегда его включать;
Pro может получить отдельные enhanced controls без полного dedicated deployment.
17. Операционная модель по tenant tier

Так как AWS рекомендует tenant-aware dashboards и views по tiers, Reva Studio должна строить operations так:

17.1 Обязательные атрибуты в telemetry

Каждый лог, метрика и trace по request business-path должен содержать:

tenant_id
plan_code
tier_code
billing_status
feature_set_version
region_code
17.2 Tenant-aware dashboards

Должны существовать dashboard views:

top tenants by load;
top tenants by failures;
top tenants by messaging volume;
plan distribution;
revenue by plan;
noisy neighbor detector;
expiring trials;
past_due tenants by MRR impact.
17.3 Support routing

Support priority определяется не только severity, но и tier:

starter = standard queue
growth = priority business queue
pro = priority queue
enterprise = account-managed escalation path
18. Entitlement registry

Каждый plan должен существовать как конфигурационный объект, а не только как маркетинговая страница.

Рекомендуемый формат:

plans:
  starter:
    tier: starter
    limits:
      branches: 1
      active_staff: 3
      seats: 1
      services: 50
      reminder_messages_included: 1000
      ai_credits_included: 0
    features:
      telegram_bot: true
      telegram_mini_app: true
      loyalty: false
      online_payments: true
      deposits: false
      advanced_analytics: false
      api_access: false
      custom_domain: false
      white_label: false
    support:
      level: standard
      onboarding_assistance: false

  growth:
    tier: growth
    limits:
      branches: 1
      active_staff: 10
      seats: 5
      services: 200
      reminder_messages_included: 5000
      ai_credits_included: 500
    features:
      telegram_bot: true
      telegram_mini_app: true
      loyalty: true
      online_payments: true
      deposits: true
      advanced_analytics: false
      api_access: limited
      custom_domain: false
      white_label: false
    support:
      level: priority_business_hours
      onboarding_assistance: true

  pro:
    tier: pro
    limits:
      branches: 3
      active_staff: 30
      seats: 15
      services: 1000
      reminder_messages_included: 15000
      ai_credits_included: 5000
    features:
      telegram_bot: true
      telegram_mini_app: true
      loyalty: true
      online_payments: true
      deposits: true
      advanced_analytics: true
      api_access: true
      custom_domain: true
      white_label: true
    support:
      level: priority
      onboarding_assistance: true

  enterprise:
    tier: enterprise
    limits:
      branches: custom
      active_staff: custom
      seats: custom
      services: custom
      reminder_messages_included: custom
      ai_credits_included: custom
    features:
      telegram_bot: true
      telegram_mini_app: true
      loyalty: true
      online_payments: true
      deposits: true
      advanced_analytics: true
      api_access: true
      custom_domain: true
      white_label: true
      sso: true
    support:
      level: enterprise
      onboarding_assistance: true
      account_manager: true
19. Рекомендуемая доменная модель
Tenant
- id
- slug
- display_name
- status
- current_plan_code
- current_tier_code
- billing_profile_id
- isolation_profile
- entitlement_set_version
- created_at
- activated_at
- archived_at

TenantPlanAssignment
- id
- tenant_id
- plan_code
- price_catalog_id
- billing_interval
- started_at
- ends_at
- cancel_at_period_end
- source
- created_by

TenantEntitlementSnapshot
- id
- tenant_id
- plan_code
- tier_code
- features_json
- limits_json
- support_json
- valid_from
- valid_to

TenantUsageCounter
- id
- tenant_id
- metric_code
- period_start
- period_end
- consumed
- included
- overage
- updated_at

TenantAddonAssignment
- id
- tenant_id
- addon_code
- quantity
- started_at
- ended_at
20. Billing integration requirements

Официальные SaaS billing systems поддерживают recurring subscriptions, seat licensing, usage billing, trials и plan upgrades. Поэтому Reva Studio должна уметь как минимум:

создать billing customer при onboarding;
создать базовую subscription;
добавить seat add-on;
учесть metered usage;
корректно переживать proration;
обработать trial conversion;
синхронизировать billing status с internal tenant state;
дедуплицировать webhook;
хранить idempotency keys.
20.1 Источник истины

Для денег источником истины остаётся billing provider и подтверждённые webhook-события.
Для product access источником истины остаётся internal entitlement snapshot после нормализованной синхронизации.

20.2 Что хранить локально

Нужно хранить:

tenant_id
plan_code
external_customer_id
external_subscription_id
external_price_id
billing_interval
trial_end_at
current_period_start
current_period_end
billing_status
cancel_at_period_end
20.3 Что не делать
не вычислять права только из live webhook payload;
не делать external API единственным источником доступа в runtime;
не включать тяжёлую permission-логику напрямую в billing adapter.
21. Плановая модель монетизации Reva Studio

Это внутренняя целевая модель.

21.1 Revenue layers

У Reva Studio должно быть минимум 4 слоя дохода:

базовая подписка;
seat overage;
metered usage;
premium add-ons.
21.2 Почему это правильно для SaaS

Потому что:

small tenants нужен low entry price;
growing tenants должны платить больше по мере роста;
very large tenants не должны быть зажаты фиксированным ceiling;
себестоимость heavy tenants должна быть отражена через usage attribution.
21.3 Чего нельзя делать
нельзя монетизировать всё только одним fixed price;
нельзя превращать каждый рост tenant в ручной sales-case;
нельзя оставлять AI и messaging без контроля consumption.