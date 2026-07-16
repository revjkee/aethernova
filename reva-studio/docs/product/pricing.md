# Pricing Strategy

## Document Status

- Product: Reva Studio
- Artifact: Pricing strategy and monetization specification
- Status: Draft for implementation
- Audience: Founder, product, finance, growth, engineering
- Scope: SaaS pricing for beauty studio management platform
- Last updated: 2026-03-23

---

## 1. Purpose

Этот документ фиксирует целевую модель монетизации Reva Studio как SaaS-платформы для салонов и студий красоты.

Документ отвечает на вопросы:

- за что именно платит клиент
- как упаковываются тарифы
- какие value metrics используются
- где заканчивается базовый тариф и начинаются add-ons
- как строится путь роста клиента от малого кабинета до сети
- какие ограничения и guardrails обязательны для финансово устойчивой модели

Документ не является бухгалтерской политикой и не подменяет собой договор, оферту, налоговую модель или локальные юридические документы.

---

## 2. Pricing Goal

Цель pricing-модели Reva Studio:

- сделать вход в продукт простым для малого бизнеса
- не ограничить рост выручки на клиента при масштабировании
- сохранить понятную self-serve модель для небольших студий
- обеспечить sales-assisted и enterprise motion для сетей и франшиз
- связать цену не только с доступом к системе, но и с реальной ценностью для бизнеса
- не создавать сильного billing-friction на старте

---

## 3. Strategic Principle

Для Reva Studio целевая модель монетизации должна быть **hybrid pricing**:

- базовая подписка за доступ к платформе
- ограниченное число включённых ресурсов
- доплата за расширение команды, филиалов и premium-функций
- отдельные add-ons для AI, аналитики, маркетинга, автоматизации и enterprise-функций
- при необходимости отдельная транзакционная логика для online payments, marketplace или leads

Такой подход соответствует общим моделям SaaS-тарификации, где subscription, per-seat, usage-based и hybrid pricing могут комбинироваться для соответствия продукту и сегменту клиента. AWS отдельно указывает, что consumption-based pricing может сочетаться с subscription, а Stripe описывает hybrid pricing как комбинацию recurring и variable components. :contentReference[oaicite:1]{index=1}

---

## 4. Product Monetization Thesis

Reva Studio продаёт не просто доступ к интерфейсу, а снижение операционного хаоса в студии.

Клиент платит за:

- управление расписанием
- снижение потерь из-за пропущенных записей и накладок
- централизованную клиентскую базу
- автоматизацию уведомлений
- контроль загрузки мастеров
- аналитику выручки и услуг
- бонусную и retention-механику
- удобный клиентский канал через Telegram / web / mini app
- дальнейшую цифровизацию бизнеса

---

## 5. Pricing Principles

## 5.1 Simplicity first

Малый салон должен понимать тариф за 30-60 секунд.

## 5.2 Expansion-ready

Клиент должен естественно расти по тарифной лестнице без миграции на новый продукт.

## 5.3 Value-linked

Цена должна быть привязана к понятным единицам ценности:

- количество активных мастеров
- количество локаций
- доступ к advanced features
- объём коммуникаций или AI usage, если это действительно существенная cost-driver зона

## 5.4 No hidden core tax

Критичные функции записи, расписания и клиентов не должны быть спрятаны за искусственными paywall, иначе продукт теряет базовую ценность.

## 5.5 Add-ons only for real differentiation

Add-ons должны продавать дополнительную ценность, а не исправлять искусственно урезанный базовый продукт.

## 5.6 Margin protection

Любая usage-компонента должна быть введена только там, где есть реальная переменная себестоимость:

- AI
- SMS
- external providers
- paid leads
- high-volume campaigns
- premium analytics workloads

---

## 6. Recommended Pricing Architecture

Итоговая модель:

`Monthly Recurring Revenue per account = Base Plan + Extra Active Staff + Extra Locations + Add-ons + Optional Transactional Components`

Где:

- `Base Plan` — доступ к платформе по выбранному пакету
- `Extra Active Staff` — доплата за мастеров сверх включённого лимита
- `Extra Locations` — доплата за филиалы сверх включённого лимита
- `Add-ons` — AI, advanced analytics, loyalty, automation, integrations, white-label, enterprise security
- `Optional Transactional Components` — usage-fees только там, где есть подтверждённая unit economics логика

---

## 7. Value Metrics

Для Reva Studio рекомендуются следующие основные value metrics.

## 7.1 Primary Metric

### Active staff seats

Основная метрика роста.

Почему:

- напрямую связана с размером студии
- легко объясняется клиенту
- масштабируется вместе с бизнесом
- не зависит от сезонного шума по количеству записей

Определение:

`active_staff_seat` — мастер, который активен в биллинговом периоде и имеет право принимать записи, управлять расписанием или участвовать в оказании услуг.

## 7.2 Secondary Metrics

### Locations
Для multi-location клиентов.

### Automation volume
Только для heavy-usage сценариев, где есть переменная себестоимость.

### AI usage
Только для функций с вычислительными затратами.

### Premium reporting scope
Только для продвинутой аналитики сетевого уровня.

## 7.3 Metrics that should not be primary at launch

Не рекомендуется делать базовой метрикой на старте:

- количество клиентов в CRM
- число записей в месяц
- число услуг в каталоге
- число календарных просмотров
- количество администраторов как отдельную главную ось цены

Причина: для малого бизнеса такие метрики хуже читаются и сильнее увеличивают pricing anxiety.

---

## 8. Customer Segments

## 8.1 Solo / Micro

Один специалист или небольшой кабинет.

Типовые признаки:

- 1-2 мастера
- один календарь
- простое расписание
- минимальная аналитика
- высокая чувствительность к цене
- self-serve onboarding

## 8.2 Small Studio

Небольшая студия.

Типовые признаки:

- 3-8 мастеров
- общая клиентская база
- нужны роли, отчёты, напоминания
- важен контроль загрузки
- нужен удобный admin workflow

## 8.3 Growing Studio

Растущая студия.

Типовые признаки:

- 8-20 мастеров
- сложнее графики
- выше риск накладок
- нужны advanced reports, loyalty, campaigns, integrations
- выше потребность в автоматизации

## 8.4 Network / Franchise / Enterprise

Сеть или франшиза.

Типовые признаки:

- несколько локаций
- разграничение доступа
- централизованная отчётность
- SLA
- security and audit requirements
- кастомные интеграции
- внедрение через sales motion

---

## 9. Recommended Packaging

Рекомендуемая упаковка на старте:

- Launch
- Studio
- Scale
- Enterprise

---

## 10. Plan Matrix

## 10.1 Launch

Целевой сегмент:

- solo
- micro
- кабинет
- мини-студия

Включает:

- online booking
- calendar and availability
- clients CRM base
- services catalog
- staff basics
- reminders in low-volume mode
- simple dashboard
- basic reports
- Telegram channel basics

Ограничения:

- включённый лимит активных мастеров: `PRICING_LAUNCH_INCLUDED_STAFF`
- включённый лимит локаций: `1`
- ограниченный набор automation features
- без enterprise security
- без advanced analytics
- без white-label

Модель оплаты:

- фиксированная ежемесячная подписка
- опциональная годовая оплата со скидкой

## 10.2 Studio

Целевой сегмент:

- полноценная студия
- основной рынок Reva Studio на старте

Включает всё из Launch, плюс:

- расширенные роли и права
- более сильная аналитика
- loyalty basics
- promotions and campaigns basics
- better reminder flows
- exports
- priority support baseline
- более высокий лимит automation

Ограничения:

- включённый лимит активных мастеров: `PRICING_STUDIO_INCLUDED_STAFF`
- включённый лимит локаций: `PRICING_STUDIO_INCLUDED_LOCATIONS`

Модель оплаты:

- базовая подписка
- доплата за extra staff seats
- доплата за extra locations

## 10.3 Scale

Целевой сегмент:

- growing studio
- студия с несколькими направлениями
- студия с сильной операционной нагрузкой

Включает всё из Studio, плюс:

- advanced analytics
- advanced loyalty
- advanced automations
- advanced permissions
- integration layer
- API access
- deeper finance and retention reporting
- AI-assisted features baseline
- higher operational limits

Ограничения:

- включённый лимит активных мастеров: `PRICING_SCALE_INCLUDED_STAFF`
- включённый лимит локаций: `PRICING_SCALE_INCLUDED_LOCATIONS`

Модель оплаты:

- базовая подписка
- extra staff seats
- extra locations
- optional AI add-on
- optional premium communication add-on

## 10.4 Enterprise

Целевой сегмент:

- сеть
- франшиза
- multi-location operator
- custom governance client

Включает всё из Scale, плюс:

- SSO / advanced access control
- audit exports
- custom SLA
- onboarding assistance
- account management
- custom integrations
- dedicated reporting
- contract billing
- white-label or partner features if needed

Модель оплаты:

- custom annual contract
- negotiated setup fee if applicable
- optional implementation package
- optional premium support package

Конкретные цены здесь не фиксируются. Без фактических данных по target segment economics я не могу подтвердить корректный price point.

---

## 11. Add-On Strategy

Add-ons допустимы только там, где есть реальная дополнительная ценность или переменная себестоимость.

## 11.1 AI Add-On

Содержит:

- AI summaries
- AI marketing suggestions
- AI schedule recommendations
- AI retention prompts
- AI admin assistant features

Использовать как add-on, потому что AI создаёт переменную cost-base.

## 11.2 Advanced Analytics Add-On

Содержит:

- cohort analysis
- repeat visit analytics
- service profitability views
- staff productivity analytics
- retention and churn signals

## 11.3 Loyalty Pro Add-On

Содержит:

- advanced loyalty rules
- bonus tiers
- partner promos
- event-triggered bonuses
- token-ready extensibility

## 11.4 Automation Add-On

Содержит:

- complex triggers
- custom automations
- multi-step workflows
- segmentation automations

## 11.5 Integrations Add-On

Содержит:

- external CRM sync
- accounting exports
- third-party messaging connectors
- webhook packages
- API limits above standard

## 11.6 White-Label Add-On

Только для enterprise / partner / franchise сегмента.

## 11.7 Premium Communications Add-On

Используется только если:

- есть значимый объём SMS или paid channels
- эти расходы materially affect gross margin

---

## 12. What Must Be Included in Core Product

Следующие функции должны быть в core-package, а не скрыты в add-ons:

- создание и управление записями
- рабочий календарь
- доступность мастера
- базовая клиентская карточка
- каталог услуг
- базовые уведомления
- роли администратора и мастера
- базовая аналитика по загрузке и выручке
- базовые отмены и переносы

Если скрыть эти функции слишком высоко по тарифной лестнице, продукт потеряет базовую конкурентоспособность.

---

## 13. What Can Be Monetized Separately

Отдельно можно монетизировать:

- AI features
- premium analytics
- advanced automations
- extra staff seats
- extra locations
- advanced integrations
- white-label
- premium support
- implementation
- custom reporting
- enterprise compliance pack

---

## 14. Billing Rules

## 14.1 Billing Period

Поддерживаемые варианты:

- monthly
- annual

Годовая оплата допустима со скидкой.

## 14.2 Seat Counting Rule

Биллинг должен считаться по `active_staff_seat`.

Рекомендуемое правило:

- мастер считается активным, если он активен на дату биллинга или был активен больше заданного порога в периоде
- deactivated staff должен переставать тарифицироваться по понятному правилу
- soft-deleted staff не должен оставаться скрытым биллинговым артефактом

## 14.3 Proration

Для mid-cycle изменений:

- при добавлении staff seats допускается proration
- при переходе на более высокий тариф допускается немедленный upgrade
- downgrade применяется со следующего периода, если иное не оговорено отдельно

## 14.4 Trial

Рекомендуется:

- бесплатный trial
- без enterprise-функций
- без heavy-cost AI usage
- без бесконтрольного SMS spend

## 14.5 Grace Period

При failed payment допустим короткий grace period с ограниченным read-only или degraded mode сценарием.

---

## 15. Discount Policy

Скидки допустимы, но должны быть формализованы.

Разрешённые типы:

- annual prepay discount
- launch cohort discount
- partner discount
- founder-led pilot discount
- educational or strategic pilot discount при отдельном решении

Запрещено:

- хаотично раздавать бессрочные скидки без price governance
- давать глубокие скидки на enterprise scope без компенсации объёма или контракта
- снижать цену ниже unit economics threshold без стратегического решения

---

## 16. Recommended Revenue Motions

## 16.1 Self-Serve

Для:

- Launch
- Studio

Характеристики:

- быстрый onboarding
- прозрачные цены
- быстрый checkout
- минимум общения с sales

## 16.2 Product-Led Expansion

Для:

- Studio
- Scale

Характеристики:

- апгрейд внутри продукта
- счётчики лимитов
- мягкие upgrade nudges
- activation of add-ons in context

## 16.3 Sales-Assisted / Enterprise

Для:

- Enterprise
- network
- franchise

Характеристики:

- demo
- commercial proposal
- negotiated contract
- custom onboarding

Paddle отдельно указывает, что для SaaS важно различать self-serve downmarket, value-based tiers для B2B и custom pricing для enterprise. :contentReference[oaicite:2]{index=2}

---

## 17. Monetization Recommendations for Reva Studio

## 17.1 Launch Recommendation

Стартовая модель должна быть максимально простой:

- 1 базовый тариф для малого сегмента
- 1 основной тариф для студий
- 1 старший тариф для растущих студий
- enterprise по запросу

## 17.2 First Expansion Vector

Первый контролируемый рычаг роста выручки:

- extra active staff seats

Это проще объясняется, чем usage на записи или клиентов.

## 17.3 Second Expansion Vector

- extra locations
- advanced analytics
- AI add-on

## 17.4 Transactional Monetization

Транзакционная монетизация допустима только в одном из сценариев:

- paid online payments
- marketplace / lead distribution
- high-cost communication channels
- premium AI usage above included quota

Если переменной себестоимости нет, лишняя usage-fee усложняет восприятие цены без пользы.

---

## 18. Price Governance

Любое изменение прайсинга должно быть версионируемым.

Обязательные поля price catalog:

- `price_version`
- `effective_from`
- `effective_to`
- `plan_code`
- `billing_period`
- `currency`
- `base_amount`
- `included_staff`
- `included_locations`
- `extra_staff_price`
- `extra_location_price`
- `addons[]`
- `trial_policy`
- `discount_rules[]`
- `grandfathering_policy`

## 18.1 Grandfathering

Для существующих клиентов должна существовать явная политика:

- сохранить старую цену
- перевести на новую цену с уведомлением
- дать переходный период
- автоматически назначить более выгодный equivalent plan

Без этой политики прайсинг становится неуправляемым.

## 18.2 Price Change Process

Минимальный процесс:

1. формулируется гипотеза
2. оценивается влияние на конверсию, expansion и support load
3. задаётся новая версия price catalog
4. проводится controlled rollout
5. анализируются результаты
6. фиксируется решение

---

## 19. Billing and Checkout Constraints

Платёжный и биллинговый контур должен поддерживать:

- subscriptions
- annual prepay
- add-ons
- proration
- seat changes
- coupons
- invoice history
- failed payment recovery
- taxes and invoicing according to target market requirements

Stripe прямо описывает recurring charges, license fees и usage-based components в рамках одной pricing-конфигурации, что подтверждает практичность гибридной биллинговой модели. :contentReference[oaicite:3]{index=3}

---

## 20. Geographic Expansion Consideration

Если Reva Studio выходит за один рынок, pricing-слой должен быть готов к:

- нескольким валютам
- локализации checkout
- корректной налоговой логике
- локальным price books
- controlled regional experiments

Paddle отдельно связывает global growth с pricing localization, tax handling и checkout localization. :contentReference[oaicite:4]{index=4}

---

## 21. Unit Economics Guardrails

Точные пороги в этом документе не фиксируются, потому что без вашей финансовой базы я не могу подтвердить корректные значения.

Но pricing-модель обязана проверяться минимум по следующим показателям:

- gross margin by plan
- support load by segment
- expansion revenue rate
- trial-to-paid conversion
- logo churn by plan
- revenue churn by plan
- payback period
- AI cost per paying account
- communications cost per paying account

Минимальное требование:

Нельзя запускать add-on или usage-ось, если она технически сложнее, чем создаваемая ею дополнительная выручка и защита маржи.

---

## 22. Packaging Rules

## 22.1 Good Packaging

Хорошая упаковка:

- объяснима за минуту
- не требует калькулятора для базового выбора
- даёт логичный upgrade path
- не создаёт ощущения ловушки

## 22.2 Bad Packaging

Плохая упаковка:

- слишком много тарифов
- слишком много мелких ограничений
- ключевая ценность спрятана за дорогим апсейлом
- основной тариф не покрывает реальный use case студии
- клиент не понимает, почему он должен перейти выше

---

## 23. Suggested Initial Price Book Structure

Ниже структура, а не конкретные публичные цены.

```yaml
pricing_catalog:
  version: "v1"
  currency_strategy:
    default_currency: "RUB"
    supported_currencies:
      - "RUB"
  plans:
    - code: "launch"
      billing_periods: ["monthly", "annual"]
      base_amount: "TBD"
      included_staff: "TBD"
      included_locations: 1
      included_features:
        - booking_calendar
        - availability
        - clients_crm_basic
        - services_catalog
        - reminders_basic
        - reporting_basic
      addons_allowed:
        - ai_assistant_basic
        - extra_staff
    - code: "studio"
      billing_periods: ["monthly", "annual"]
      base_amount: "TBD"
      included_staff: "TBD"
      included_locations: "TBD"
      included_features:
        - booking_calendar
        - availability
        - clients_crm
        - services_catalog
        - reminders_standard
        - reporting_standard
        - loyalty_basic
        - promotions_basic
      addons_allowed:
        - ai_assistant
        - analytics_pro
        - automation_pro
        - extra_staff
        - extra_location
    - code: "scale"
      billing_periods: ["monthly", "annual"]
      base_amount: "TBD"
      included_staff: "TBD"
      included_locations: "TBD"
      included_features:
        - booking_calendar
        - availability
        - clients_crm
        - loyalty_pro
        - analytics_pro
        - automation_pro
        - integrations_standard
        - api_access
      addons_allowed:
        - ai_assistant_pro
        - premium_communications
        - extra_staff
        - extra_location
    - code: "enterprise"
      billing_periods: ["annual", "custom"]
      pricing: "custom"
      included_features:
        - sso
        - audit_exports
        - advanced_security
        - custom_integrations
        - premium_support
        - dedicated_reporting
        - multi_location_governance
  add_ons:
    - code: "extra_staff"
      pricing: "per_active_staff"
    - code: "extra_location"
      pricing: "per_location"
    - code: "ai_assistant"
      pricing: "fixed_or_hybrid"
    - code: "analytics_pro"
      pricing: "fixed"
    - code: "automation_pro"
      pricing: "fixed"
    - code: "premium_communications"
      pricing: "usage_based_if_cost_driver"