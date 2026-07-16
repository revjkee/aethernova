# Partner Strategy

## Status

Approved

## Document Type

Product strategy

## Purpose

Этот документ определяет партнёрскую стратегию Reva Studio как масштабируемой Beauty/SaaS платформы.

Документ нужен для того, чтобы:
- зафиксировать, кто считается партнёром в системе;
- определить, зачем партнёрская модель нужна продукту и бизнесу;
- описать уровни партнёрства;
- определить продуктовые, операционные и финансовые принципы;
- задать рамки для backend, frontend, CRM, бонусной системы, аналитики и юридического контура;
- обеспечить единое понимание между product, engineering, operations, marketing и founders.

## Scope

Документ покрывает:
- партнёров-специалистов;
- партнёров-студии;
- партнёров-инфлюенсеров и реферальных амбассадоров;
- B2B-партнёров;
- платформенные роли;
- целевую экономику партнёрского направления;
- требования к продукту и данным;
- риски и ограничения;
- этапы внедрения.

Документ не покрывает в полном объёме:
- юридические договоры;
- бухгалтерский учёт;
- налоговую модель;
- финальные тарифы;
- точную комиссионную сетку;
- финальную токеномику бонусов.

Эти части должны быть уточнены отдельными документами и ADR.

## Context

Reva Studio развивается как платформа для beauty-услуг с возможностью расширения в сторону:
- multi-master операционной модели;
- партнёрской сети;
- loyalty и bonus economy;
- referral и ambassador mechanics;
- partner-facing кабинета;
- white-label или franchise-подобного контура в будущем.

На текущем этапе продукт должен проектироваться так, чтобы:
- один бизнес мог расти без полного ручного управления;
- новые мастера и партнёры могли подключаться по стандартизированному процессу;
- мотивация партнёров была прозрачной;
- данные по партнёрам были доступны для аналитики и антифрода;
- дальнейший рост не ломал архитектуру.

Не могу подтвердить текущую фактическую юнит-экономику, LTV, CAC, churn, retention и средний чек Reva Studio, поскольку исходные операционные данные не предоставлены.

## Strategic Thesis

Партнёрская модель для Reva Studio нужна не как дополнительная опция, а как один из основных рычагов роста.

Ключевая идея:
Reva Studio должна уметь расти не только за счёт внутренних мастеров и прямого маркетинга, но и за счёт сети внешних и внутренних партнёров, для которых участие в платформе создаёт измеримую ценность.

Партнёрская стратегия должна давать четыре результата:
1. Рост клиентской базы.
2. Рост количества услуг и доступных слотов.
3. Рост выручки платформы без линейного роста ручного управления.
4. Формирование устойчивой экосистемы, где партнёрам выгодно оставаться внутри платформы.

## Business Objectives

### Primary Objectives

1. Увеличить supply-сторону платформы через подключение мастеров и студий.
2. Снизить зависимость от одного канала привлечения клиентов.
3. Создать повторяемую модель масштабирования в другие районы, города или ниши.
4. Повысить lifetime value экосистемы через партнёрские кабинеты, бонусы и встроенные механики удержания.
5. Подготовить базу для будущей platform economy, где партнёр участвует не только в оказании услуги, но и в росте сети.

### Secondary Objectives

1. Получить дополнительный канал контента и доверия через инфлюенсеров и амбассадоров.
2. Создать опорную сеть B2B-интеграций.
3. Повысить плотность записей и загрузку мастеров.
4. Снизить ручной хаос в расчётах, бонусах и атрибуции.
5. Создать прозрачную основу для future tokenized loyalty mechanics.

## Partner Types

### 1. Service Partner

Это мастер или специалист, который оказывает услуги через платформу Reva Studio.

Примеры:
- мастер ногтевого сервиса;
- бровист;
- лэшмейкер;
- визажист;
- массажист;
- будущие категории, такие как солярий или смежные beauty-сервисы.

### 2. Studio Partner

Это внешняя студия или салон, который подключается к платформе как отдельный поставщик услуг.

Модель подходит для сценариев:
- расширения географии;
- объединения нескольких локаций;
- создания партнёрской сети;
- запуска marketplace-режима.

### 3. Ambassador Partner

Это физическое лицо или микроинфлюенсер, который приводит клиентов или мастеров в систему.

Основная ценность:
- привлечение трафика;
- доверительный social proof;
- реферальный рост;
- локальное распространение бренда.

### 4. B2B Partner

Это компания или внешний сервис, который создаёт дополнительную ценность экосистеме.

Примеры:
- поставщики расходников;
- образовательные платформы;
- CRM и finance integrations;
- партнёры по рекламе;
- локальные бренды и коллаборации.

### 5. Strategic Partner

Это партнёр, который влияет не только на revenue, но и на инфраструктурный рост платформы.

Примеры:
- крупная студия;
- сеть мастеров;
- франчайзинговый кандидат;
- канал дистрибуции;
- технологический интеграционный партнёр.

## Partner Value Proposition

### Value for Service Partners

Платформа должна давать мастеру:
- поток клиентов;
- удобную запись;
- управление расписанием;
- прозрачную статистику;
- понятные выплаты и бонусы;
- снижение хаоса в коммуникациях;
- инструменты удержания клиента;
- возможность растить личный бренд внутри платформы.

### Value for Studio Partners

Платформа должна давать студии:
- витрину услуг;
- централизованное управление мастерами;
- бронирование;
- прозрачную аналитику;
- контроль над загрузкой;
- unified customer activity;
- бонусные и партнёрские механики;
- масштабируемый digital layer поверх офлайн-бизнеса.

### Value for Ambassadors

Платформа должна давать амбассадору:
- понятную реферальную механику;
- прозрачную атрибуцию;
- быстрый расчёт вознаграждения;
- личный кабинет или хотя бы tracking view;
- понятные статусы;
- отсутствие ручных споров по учёту приглашений.

### Value for B2B Partners

Платформа должна давать B2B-партнёру:
- интеграционный канал;
- доступ к аудитории;
- совместные кампании;
- измеримость результата;
- управляемость условий;
- цифровой контур взаимодействия.

## Strategic Principles

### 1. Platform First

Партнёрская стратегия должна строиться не вокруг ручных договорённостей, а вокруг платформенных сущностей и процессов.

То есть:
- каждый партнёр имеет тип;
- каждый партнёр имеет статус;
- каждая выплата или бонус атрибутируется;
- каждое действие имеет audit trail;
- каждая сущность имеет owner, lifecycle и metrics.

### 2. Transparent Economics

Любая партнёрская механика должна быть измерима и объяснима.

Нельзя строить партнёрскую модель на:
- ручных обещаниях;
- неформальных расчётах;
- неотслеживаемых бонусах;
- неоднозначных условиях конверсии.

### 3. Modular Growth

Партнёрская стратегия должна внедряться поэтапно:
- сначала мастера и базовый referral;
- затем ambassador layer;
- затем студии и multi-location;
- затем B2B и strategic layer;
- затем расширенные bonus and tokenized mechanics.

### 4. No Hidden Coupling

Партнёрские механики не должны быть жёстко пришиты к одному каналу продаж, одному сотруднику или одному ручному процессу.

### 5. Data Before Scale

Прежде чем масштабировать партнёрскую сеть, платформа должна уметь:
- корректно атрибутировать источник;
- считать конверсии;
- считать выплаты;
- видеть retention;
- видеть fraud signals;
- делать cohort analysis.

## Target Operating Model

### Stage A. Single Studio Partner-Ready Core

На этом этапе Reva Studio остаётся одной операционной студией, но внутренне проектируется как partner-ready система.

Что должно быть заложено:
- роли партнёров;
- реферальный контур;
- бонусный контур;
- partner identifiers;
- базовая аналитика;
- ledger-like учёт начислений;
- audit trail;
- разграничение доступа.

### Stage B. Multi-Master Structured Partnering

На этом этапе каждый мастер внутри экосистемы становится управляемой бизнес-сущностью:
- с профилем;
- загрузкой;
- метриками;
- индивидуальными бонусами;
- возможным партнёрским статусом;
- отдельной экономикой по услугам.

### Stage C. Ambassador Layer

На этом этапе запускается отдельный контур для людей, которые приводят клиентов или мастеров.

Минимальные функции:
- инвайт-код или referral link;
- tracking статусов;
- правила квалификации;
- reward calculation;
- anti-fraud;
- campaign control.

### Stage D. Studio Partner Network

На этом этапе внешний салон или студия может подключиться как отдельная операционная единица.

Нужны:
- multi-tenant ready модель или controlled multi-org layer;
- изоляция данных;
- общая платформа бронирования;
- единая аналитика верхнего уровня;
- права доступа;
- конфигурация услуг, графиков, сотрудников и выплат.

### Stage E. Strategic Ecosystem Layer

На этом этапе Reva Studio становится экосистемой:
- с network effects;
- with partner dashboards;
- with revenue-share models;
- with B2B integrations;
- with loyalty economy;
- with future-ready token logic.

## Revenue Models

Не могу подтвердить, какая именно финансовая модель уже принята в Reva Studio. Ниже дан целевой перечень допустимых моделей.

### Model 1. Commission per Booking

Платформа удерживает комиссию с успешной записи или завершённой услуги.

Подходит для:
- мастеров;
- внешних партнёров;
- marketplace-like логики.

Плюсы:
- прозрачно;
- масштабируемо;
- привязано к фактическому объёму бизнеса.

Риски:
- требует точной атрибуции статуса услуги;
- требует понятной политики отмен и возвратов.

### Model 2. Subscription for Partners

Партнёр платит подписку за доступ к платформенным функциям.

Подходит для:
- студий;
- сильных мастеров;
- B2B-партнёров;
- white-label сценариев.

Плюсы:
- предсказуемая выручка;
- меньше споров по микрокомиссиям.

Риски:
- выше барьер входа;
- требует сильного набора функций.

### Model 3. Hybrid

Сочетание подписки и комиссии.

Подходит для:
- зрелой платформы;
- разных сегментов партнёров;
- стратегических партнёров.

### Model 4. Lead Fee

Платформа берёт оплату за подтверждённый лид или квалифицированную запись.

Подходит для:
- ambassador mechanics;
- B2B traffic partnerships;
- campaign-based cooperation.

### Model 5. Revenue Share

Партнёр и платформа делят доход по заранее зафиксированным правилам.

Подходит для:
- стратегических студий;
- инфлюенсеров;
- образовательных и supply-side партнёров.

## Recommended Initial Model

Для раннего этапа рекомендуется следующая продуктовая логика:
- Service Partners: controlled commission model;
- Ambassadors: qualification-based referral reward;
- Studio Partners: pilot-based hybrid model;
- B2B Partners: case-by-case model;
- Strategic Partners: negotiated revenue-share with auditability.

Это не факт о текущей модели Reva Studio, а рекомендуемая целевая стратегия.

## Product Requirements

### Partner Identity Layer

Платформа должна различать:
- customer;
- staff;
- master;
- partner;
- studio partner;
- ambassador;
- admin;
- system actor.

Один субъект может иметь несколько ролей, но роли должны быть разделены логически и в правах доступа.

### Partner Profile

Для каждого партнёра должен существовать структурированный профиль.

Минимальные поля:
- `partner_id`
- `partner_type`
- `status`
- `display_name`
- `legal_name`
- `contacts`
- `owner_user_id`
- `region`
- `service_categories`
- `commission_plan_id`
- `payout_method`
- `tax_mode`
- `created_at`
- `updated_at`

### Partner Status Lifecycle

Рекомендуемые статусы:
- `draft`
- `pending_review`
- `active`
- `paused`
- `suspended`
- `archived`

### Partner Financial Layer

Нужны:
- commission plans;
- reward rules;
- payout tracking;
- debt and correction support;
- adjustment history;
- idempotent accrual logic.

### Partner Analytics Layer

Нужны:
- attributed leads;
- bookings;
- completed services;
- paid services;
- gross revenue;
- net revenue;
- partner payout;
- conversion rate;
- repeat rate;
- cancellation rate;
- fraud flags.

### Partner Access Layer

Нужны отдельные интерфейсы:
- partner dashboard;
- ambassador dashboard;
- studio dashboard;
- admin control plane.

## Economic Rules

### Core Requirements

1. Любое начисление должно иметь источник.
2. Любая комиссия должна иметь расчётную базу.
3. Любой бонус должен иметь qualification rule.
4. Любая выплата должна быть трассируема.
5. Любая корректировка должна быть журналируема.
6. Любой reversal должен быть возможен по политике.
7. Любая спорная операция должна иметь reason code.

### Minimum Financial Objects

- `partner_commission_plan`
- `partner_reward_rule`
- `partner_ledger_entry`
- `partner_payout_request`
- `partner_adjustment`
- `partner_settlement_period`

## Referral and Ambassador Strategy

Партнёрская стратегия должна быть связана с реферальным доменом, но не сводиться к нему.

### Separation of Concepts

Нужно разделять:
- referral for customer growth;
- partner referral for master growth;
- ambassador program for traffic acquisition;
- strategic partnership for business expansion.

Это разные механики, даже если у них схожая инфраструктурная база.

### Ambassador Qualification Examples

Возможные условия:
- первый оплаченный визит приглашённого клиента;
- первая завершённая запись;
- регистрация и достижение определённого порога;
- подключение нового мастера;
- активация студии-партнёра.

Не могу подтвердить, какой qualification event выбран в Reva Studio. Это должно быть закреплено отдельно.

## Studio Partnership Strategy

### Why Studio Partnerships Matter

Подключение внешних студий может дать:
- более быстрый geographic expansion;
- рост предложения без полного CAPEX на новые точки;
- рост network effects;
- увеличение GMV платформы;
- усиление бренда как экосистемы.

### Preconditions

Перед подключением внешних студий должны существовать:
- роль studio partner;
- разграничение доступа;
- локации как отдельные сущности;
- staff assignment model;
- pricing and catalog isolation;
- central policy layer;
- reporting layer;
- settlement layer.

### Risks

- конфликт интересов между собственными и внешними мастерами;
- сложность поддержки SLA;
- uneven service quality;
- споры по выплатам и атрибуции;
- необходимость более строгого moderation layer.

## B2B Partnership Strategy

### B2B Partner Categories

1. Supply partners.
2. Education partners.
3. Distribution partners.
4. Technology partners.
5. Marketing partners.

### Product Objective

B2B-партнёр должен приносить хотя бы одну из трёх вещей:
- revenue;
- reach;
- retention.

Если партнёр не усиливает ни один из этих контуров, его интеграционная ценность должна быть пересмотрена.

## Platform Architecture Implications

Партнёрская стратегия влияет на архитектуру напрямую.

Нужны отдельные или связанные домены:
- partners
- referrals
- loyalty
- rewards
- payouts
- audit
- analytics
- identity-access
- locations
- staff
- services_catalog
- bookings
- payments
- notifications

### Required Cross-Domain Contracts

1. `partners` должен знать, кто является партнёром и в каком статусе он находится.
2. `referrals` должен знать, кто кого привёл.
3. `bookings` должен давать событие квалификации.
4. `payments` должен подтверждать платные события.
5. `loyalty` или `rewards` должен исполнять начисления.
6. `audit` должен сохранять trail.
7. `analytics` должен строить партнёрские воронки.
8. `identity-access` должен ограничивать роли и доступ.

## Data Model Recommendations

### Core Entities

#### Partner
Основная партнёрская сущность.

#### PartnerOrganization
Организация или студия, если партнёр работает как бизнес-единица.

#### PartnerMembership
Связь пользователя и партнёрской организации.

#### PartnerCommissionPlan
Правила расчёта комиссии.

#### PartnerRewardRule
Правила бонусов и вознаграждений.

#### PartnerAttribution
Факт привязки клиента, мастера или студии к партнёру.

#### PartnerLedgerEntry
Финансово-значимая запись по расчётам.

#### PartnerPayout
Заявка или факт выплаты.

#### PartnerCampaign
Маркетинговая или growth-кампания для партнёров.

## Metrics

Не могу подтвердить фактические KPI Reva Studio. Ниже дан рекомендуемый набор метрик.

### Acquisition Metrics
- partner_signups_total
- active_partners_total
- ambassadors_total
- studio_partners_total
- partner_activation_rate

### Growth Metrics
- partner_attributed_leads_total
- partner_attributed_bookings_total
- partner_attributed_paid_bookings_total
- partner_conversion_rate
- partner_repeat_rate

### Revenue Metrics
- partner_gmv_total
- partner_net_revenue_total
- partner_payout_total
- partner_reward_cost_total
- average_revenue_per_partner

### Risk Metrics
- partner_fraud_flags_total
- duplicate_reward_attempts_total
- disputed_payouts_total
- reversal_rate

### Retention Metrics
- partner_30d_retention
- partner_90d_retention
- ambassador_reactivation_rate
- studio_partner_churn_rate

## Anti-Fraud and Trust

Партнёрская модель без антифрода становится источником утечек денег и конфликтов.

Минимально обязательны:
- self-referral prevention;
- duplicate attribution prevention;
- duplicate payout prevention;
- idempotent event handling;
- review queue for suspicious cases;
- reason codes for rejection;
- audit log for manual decisions;
- soft freeze for suspicious partner accounts.

## Legal and Compliance Constraints

Не могу подтвердить применимую юрисдикцию, налоговый режим и договорную модель Reva Studio. Эти части должны быть согласованы отдельно.

Минимально должны быть определены:
- кто является исполнителем услуги;
- кто получает оплату;
- кто несёт ответственность перед клиентом;
- как оформляется агентская или иная схема;
- как считаются и удерживаются комиссии;
- как оформляются бонусы и скидки;
- как обрабатываются персональные данные партнёров.

## Rollout Strategy

### Phase 1. Internal Structuring

Цель:
превратить текущую студию в partner-ready system без внешнего усложнения.

Что внедряется:
- partner domain model;
- partner roles;
- commission-ready structures;
- referral-ready structures;
- analytics-ready events;
- audit-ready actions.

### Phase 2. Controlled Ambassador Program

Цель:
запустить контролируемую механику привлечения клиентов.

Что внедряется:
- ambassador identities;
- referral codes;
- qualification events;
- reward rules;
- dashboard view;
- anti-fraud.

### Phase 3. Master Partnership Layer

Цель:
дать мастерам более явный статус и цифровую модель участия.

Что внедряется:
- partner profiles for masters;
- commission plans;
- performance analytics;
- payout views.

### Phase 4. Studio Partner Pilot

Цель:
подключить ограниченное число внешних студий или команд.

Что внедряется:
- organization profiles;
- multi-location support;
- scoped access;
- settlement logic;
- partner reports.

### Phase 5. Strategic Ecosystem Expansion

Цель:
масштабировать платформу как экосистему.

Что внедряется:
- advanced partner dashboards;
- B2B integrations;
- partner campaigns;
- ecosystem-level loyalty;
- future token-connected rewards.

## Product Decisions That Must Be Fixed via ADR

Следующие решения нельзя оставлять неявными:

1. Какая модель выплат будет основной.
2. Кто считается партнёром на уровне домена.
3. Может ли мастер одновременно быть staff и partner.
4. Какая qualification logic используется для ambassador rewards.
5. Можно ли суммировать партнёрскую награду с promo и loyalty.
6. Как работает reversal after cancellation or refund.
7. Какая изоляция данных нужна для studio partners.
8. Нужен ли единый ledger или несколько bounded financial ledgers.
9. Какая модель multi-tenancy допустима.
10. Как будет устроен partner moderation flow.

## Recommended ADR List

- ADR: Partner domain boundaries
- ADR: Partner commission model
- ADR: Ambassador qualification and reward policy
- ADR: Partner payout and settlement policy
- ADR: Studio partner access isolation
- ADR: Partner ledger and adjustments
- ADR: Partner fraud review policy
- ADR: Partner analytics event model

## Risks

### Product Risks
- слишком раннее усложнение;
- перегрузка команды ручным сопровождением партнёров;
- неочевидная ценность для партнёров;
- конфликт между внутренними и внешними участниками.

### Engineering Risks
- отсутствие идемпотентности;
- слабая атрибуция;
- смешение ролей;
- отсутствие audit trail;
- слабая аналитическая база;
- неправильная изоляция данных.

### Business Risks
- партнёр не окупается;
- спорная комиссионная модель;
- завышенная стоимость привлечения;
- leakage на бонусах;
- низкая активация партнёров;
- высокая доля некачественного supply.

## Non-Negotiable Requirements

1. Все партнёрские начисления должны быть трассируемы.
2. Все спорные кейсы должны быть объяснимы.
3. Все ручные действия должны журналироваться.
4. Все статусы партнёров должны быть явными.
5. Все выплаты должны быть привязаны к расчётной логике.
6. Все qualification events должны быть воспроизводимы.
7. Все интеграции должны быть безопасны к повторной доставке событий.
8. Все аналитические сущности должны иметь стабильные identifiers.

## Success Criteria

Партнёрская стратегия считается реализуемой, если:
- партнёра можно создать, активировать, приостановить и архивировать;
- источник клиента или мастера можно атрибутировать;
- расчёт награды или комиссии повторяем и объясним;
- спорные начисления можно расследовать;
- аналитика видит воронку от партнёра до выручки;
- подключение нового партнёра не требует хаотичных ручных действий;
- архитектура готова к расширению на studio network.

## Summary

Партнёрская стратегия Reva Studio должна строиться как platform strategy, а не как набор ручных договорённостей.

Целевая модель:
- мастера и студии являются управляемыми партнёрскими сущностями;
- амбассадоры и рефералы имеют прозрачную атрибуцию;
- комиссии, бонусы и выплаты считаются детерминированно;
- данные пригодны для аналитики, антифрода и аудита;
- архитектура с самого начала готова к росту в экосистему.

Это создаёт основу не только для роста текущей студии, но и для превращения Reva Studio в масштабируемую beauty platform.