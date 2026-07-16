# Reva Studio Product Roadmap

## Status

Approved as target product roadmap baseline

## Document Purpose

Этот документ фиксирует продуктовый roadmap Reva Studio как развивающейся платформы в индустрии красоты.

Документ нужен для того, чтобы:

- синхронизировать стратегию продукта, архитектуры и операционной реализации
- определить этапы развития от внутреннего operational продукта студии к SaaS-платформе
- зафиксировать приоритеты, зависимости, KPI и критерии готовности
- не допустить хаотичного расширения функциональности
- дать единый ориентир для product, backend, frontend, DevOps, analytics и growth-направлений

---

## Product Vision

Reva Studio должна эволюционировать из внутреннего цифрового ядра одной студии в промышленную beauty SaaS platform с возможностью масштабирования на множество салонов, мастеров и клиентов.

Финальная целевая модель продукта:

- операционное ядро для записи, расписания, клиентов, мастеров и услуг
- CRM и retention-механики
- loyalty и бонусная система
- платежи и финансовые сценарии
- AI-assisted workflows для операционного ускорения
- Telegram-first и mobile-friendly клиентский опыт
- multi-tenant основа для подключения внешних салонов
- платформенные инструменты аналитики, маркетинга и администрирования
- дальнейшая эволюция в ecosystem layer с marketplace-элементами

---

## Product Mission

Сделать платформу, которая одновременно:

- упрощает жизнь клиенту
- увеличивает загрузку мастеров
- снижает операционный хаос внутри студии
- повышает возврат клиентов
- улучшает управляемость бизнеса
- создаёт технологическую основу для масштабирования на другие салоны

---

## Strategic Product Thesis

Reva Studio не должна пытаться стать "всем сразу".

Правильная стратегия развития:

1. Сначала построить безошибочное operational core для собственной студии
2. Затем усилить retention, CRM, loyalty и payments
3. Потом стандартизировать платформенные контуры
4. После этого включать multi-tenant и B2B SaaS-режим
5. И только затем разворачивать marketplace и ecosystem-направления

---

## Product Principles

### 1. Operations first

Если система не помогает студии ежедневно работать быстрее и точнее, продукт не готов.

### 2. Booking is the core

Запись, расписание и загрузка мастеров являются сердцем продукта.

### 3. Retention before vanity features

Возврат клиента и LTV важнее декоративного функционала.

### 4. SaaS readiness from day one

Даже на стадии одной студии архитектура и продуктовые решения не должны блокировать multi-tenant эволюцию.

### 5. Telegram and mobile are first-class surfaces

Клиентский путь должен быть удобен через Telegram и мобильные интерфейсы.

### 6. Data must become a product capability

Аналитика должна быть не вторичным отчётом, а частью управленческой системы.

### 7. AI must reduce workload, not add complexity

AI-функции внедряются только там, где реально сокращают ручной труд и ускоряют принятие решений.

---

## Product Scope Layers

Roadmap делится на 5 уровней зрелости продукта:

### Layer 1. Operational Core

Базовое ядро работы студии:

- клиенты
- мастера
- услуги
- запись
- расписание
- отмены
- переносы
- статусы визитов
- базовые уведомления

### Layer 2. Business Control

Управление процессами и деньгами:

- роли и права
- история клиента
- депозиты и платежные сценарии
- аналитика загрузки
- отчёты по мастерам
- операционный дашборд
- аудит действий

### Layer 3. Retention and CRM

Повторные продажи и удержание:

- бонусы
- сегментация клиентов
- триггерные сообщения
- акции
- напоминания
- возвращающие кампании
- no-show механики

### Layer 4. SaaS Platformization

Переход к платформе:

- tenant isolation
- конфигурация per salon
- собственные политики и тарифы
- брендируемые настройки
- self-service onboarding
- биллинг tenant-уровня
- support/admin tooling

### Layer 5. Marketplace and Ecosystem

Расширение за пределы одного продукта:

- партнерские витрины
- внешний marketplace услуг и специалистов
- referral economy
- токенизированная loyalty-модель
- AI-powered partner tooling
- platform APIs

---

## Product Maturity Stages

### Stage A. Studio OS

Reva Studio как цифровая операционная система для одной студии.

### Stage B. Growth Engine

Reva Studio как система роста выручки, загрузки и удержания.

### Stage C. SaaS Platform

Reva Studio как повторяемый продукт для других студий.

### Stage D. Beauty Ecosystem

Reva Studio как платформа и экосистема с network effects.

---

## Roadmap Structure

Roadmap разделён на следующие горизонты:

- Horizon 1: Foundation
- Horizon 2: Core Business Optimization
- Horizon 3: Retention and Revenue Expansion
- Horizon 4: SaaS Enablement
- Horizon 5: Platform Expansion

---

## Horizon 1. Foundation

## Goal

Построить надёжное operational ядро для собственной студии.

## Product Objective

Система должна закрывать ежедневный цикл работы студии без критических ручных разрывов.

## Core Outcomes

- запись клиента становится системной и предсказуемой
- календарная занятость мастеров контролируется централизованно
- клиентская история начинает собираться в одном месте
- снижается количество ручной путаницы
- Telegram становится рабочим фронтом взаимодействия

## Major Deliverables

### 1. Identity and Access Baseline

- авторизация сотрудников
- роли: admin, manager, staff
- базовый RBAC
- аудит входа и критичных действий

### 2. Clients Baseline

- профиль клиента
- контакты
- заметки
- теги
- история визитов
- статус согласий и коммуникаций

### 3. Services Catalog

- категории услуг
- длительность
- цены
- активность услуги
- привязка услуги к типам мастеров

### 4. Staff Module

- профили мастеров
- рабочие графики
- статусы активности
- выходные и исключения
- специализации

### 5. Bookings Core

- создание записи
- подтверждение
- перенос
- отмена
- check-in
- completion
- no-show
- защита от конфликтов слотов

### 6. Notifications Baseline

- подтверждение записи
- напоминание о записи
- уведомление об отмене
- уведомление о переносе

### 7. Admin Operational UI

- список записей
- календарный режим
- фильтры по мастеру и дате
- базовые действия над записью

### 8. Telegram Operational Flow

- клиентская запись
- просмотр ближайшей записи
- отмена или перенос по правилам
- уведомления

## Success Criteria

- основные операции записи проходят без ручного обхода системы
- у менеджера есть единый календарь
- у мастеров есть понятная загрузка
- клиент может пройти базовый self-service путь
- минимизированы двойные записи и потери контекста

## Exit Criteria

Horizon 1 считается завершённым, если:

- operational booking flow работает стабильно
- роли и базовый доступ работают
- история клиента сохраняется
- студия реально использует систему ежедневно
- основные ошибки и разрывы обнаружены и закрыты

---

## Horizon 2. Core Business Optimization

## Goal

Сделать продукт не просто рабочим, а управляемым и коммерчески полезным.

## Product Objective

У руководителя студии должен появиться контроль над загрузкой, потерями, качеством записи и операционной дисциплиной.

## Core Outcomes

- становится видна реальная загрузка
- фиксируются отмены и no-show
- появляются операционные метрики
- сотрудники работают в общей логике процесса
- ручные коммуникации сокращаются

## Major Deliverables

### 1. Advanced Booking Policies

- правила подтверждения
- политики переноса
- политики отмены
- hold/expiration логика
- ограничения по окнам записи

### 2. Deposit and Payment Readiness

- обязательность депозита для отдельных сценариев
- фиксация payment status на уровне записи
- подготовка к интеграции PSP
- возвратные и частично возвратные сценарии

### 3. Schedule Intelligence

- буферы между услугами
- ограничения по ресурсам
- исключения в расписании
- правила перегрузки мастера
- специальные окна под VIP или сложные услуги

### 4. Staff Performance View

- количество записей
- completed rate
- cancellation rate
- no-show related impact
- загрузка по мастеру

### 5. Daily Operations Dashboard

- предстоящие записи
- проблемные записи
- не подтверждённые записи
- no-show сигналы
- перегруженные интервалы

### 6. Audit and Compliance Layer

- журнал изменений записей
- actor tracking
- reason codes
- системные и пользовательские действия

### 7. Basic Reporting

- записи по дням
- загрузка по мастерам
- популярные услуги
- отмены
- no-show
- первичные показатели возврата

## Success Criteria

- менеджер видит реальную картину работы студии
- ошибки и конфликты стали измеримыми
- денежные и операционные риски стали управляемыми
- продукт помогает принимать решения, а не только хранить данные

## Exit Criteria

- есть стабильный набор операционных дашбордов
- no-show и cancellations измеряются
- payment/deposit readiness встроена в booking flow
- аудит покрывает критические изменения

---

## Horizon 3. Retention and Revenue Expansion

## Goal

Превратить продукт в систему роста выручки и удержания клиентов.

## Product Objective

Каждая запись должна работать не только как операция, но и как точка возврата клиента и роста LTV.

## Core Outcomes

- появляется система повторных визитов
- маркетинг становится сегментированным
- продукт начинает управлять удержанием
- loyalty перестаёт быть декоративной функцией

## Major Deliverables

### 1. Loyalty Engine v1

- бонусный баланс
- правила начисления
- правила списания
- события начисления после completed booking
- журнал бонусных операций

### 2. CRM Segmentation

- новые клиенты
- активные клиенты
- клиенты с риском оттока
- VIP клиенты
- no-show risk клиенты
- неактивные клиенты

### 3. Triggered Messaging

- welcome message
- reminder flows
- post-visit follow-up
- reactivation campaigns
- birthday or anniversary mechanics
- abandoned booking reminders

### 4. Client History and Recommendations

- история услуг
- предпочтения
- повторяемые паттерны
- рекомендации следующих визитов
- заметки для персонала

### 5. Promotions Engine v1

- промокоды
- персональные предложения
- скидки на повторный визит
- активационные кампании по сегментам

### 6. No-Show and Risk Management

- клиентские risk flags
- обязательная предоплата для риск-групп
- ограничения на способ записи
- аналитика потерь

### 7. Revenue Analytics

- повторные записи
- retention cohorts
- LTV proxies
- средний чек
- доход по мастерам
- доход по услугам
- результативность акций

## Success Criteria

- увеличивается доля повторных визитов
- уменьшается no-show
- появляется управляемый retention loop
- loyalty используется как бизнес-инструмент, а не просто баллы

## Exit Criteria

- loyalty engine работает end-to-end
- сегментация клиентов используется в коммуникациях
- reactivation and reminder flows работают стабильно
- revenue analytics доступны управленческой роли

---

## Horizon 4. SaaS Enablement

## Goal

Подготовить продукт к превращению в масштабируемую beauty SaaS platform.

## Product Objective

Система должна перестать быть "только под одну студию" и стать платформенно готовой.

## Core Outcomes

- tenant isolation становится реальным контуром
- политики, настройки и конфигурации выносятся на tenant-уровень
- появляется основа для внешнего подключения новых салонов
- операционный код и данные перестают быть жёстко привязаны к одному бизнесу

## Major Deliverables

### 1. Multi-Tenant Core

- tenant model
- tenant-aware authorization
- tenant-scoped data access
- tenant configuration storage
- tenant branding and locale settings

### 2. Tenant Policy Engine

- свои правила отмены
- свои правила подтверждения
- свои настройки loyalty
- свои роли и ограничения
- свои бизнес-таймзоны

### 3. SaaS Admin Console

- создание tenant
- управление тарифом
- управление лимитами
- просмотр health and usage
- tenant support tools

### 4. Billing for Tenants

- тарифные планы
- usage-related metrics
- invoice/readiness model
- subscription management baseline

### 5. Self-Service Onboarding

- создание пространства салона
- первичная настройка мастеров и услуг
- импорт клиентов
- шаблоны конфигурации
- guided setup flow

### 6. White-Label and Branding Layer

- логотип
- имя салона
- цвета
- тексты
- публичные ссылки
- клиентские шаблоны сообщений

### 7. Platform Observability

- tenant usage metrics
- tenant health dashboards
- billing and usage anomalies
- tenant-level audit and incident visibility

## Success Criteria

- новая студия может быть заведена как отдельный tenant
- tenant изолирован по данным и правилам
- продукт можно повторяемо развернуть для нового бизнеса
- появляется платёжная и операционная модель SaaS

## Exit Criteria

- multi-tenant модель работает без смешения данных
- self-service onboarding закрывает базовый путь запуска
- billing and plan management готовы к внешнему использованию
- support/admin tooling покрывает первые SaaS-сценарии

---

## Horizon 5. Platform Expansion

## Goal

Расширить Reva Studio в экосистемный продукт с network effects и новыми revenue layers.

## Product Objective

После устойчивого SaaS-фундамента начать строить платформенные эффекты поверх ядра.

## Core Outcomes

- продукт получает внешние точки роста
- появляются partner and marketplace scenarios
- данные и AI используются как конкурентное преимущество
- loyalty и ecosystem инструменты становятся стратегическим активом

## Major Deliverables

### 1. Partner Marketplace Foundation

- каталог партнеров
- витрина услуг
- referral mechanics
- marketplace routing policies
- visibility rules

### 2. API and Integrations Layer

- external API
- webhook platform
- partner auth
- integration management
- audit for external usage

### 3. AI Assistant Layer

- AI for operator support
- AI for scheduling suggestions
- AI for client segmentation hints
- AI for campaign recommendations
- AI for revenue anomaly explanations

### 4. Advanced Growth Engine

- campaign scoring
- automated retention playbooks
- dynamic offers
- service recommendations
- smart reminder timing

### 5. Tokenized Loyalty or Points Evolution

- расширение бонусной модели
- универсальный reward layer
- межсервисное использование points
- partner-compatible reward mechanics

### 6. Ecosystem Analytics

- tenant benchmarking
- service trend analysis
- demand forecasting
- cross-tenant learnings with privacy boundaries

## Success Criteria

- появляются новые revenue channels помимо core SaaS
- продукт становится сложнее заменить
- ecosystem features усиливают LTV и retention
- внешние участники получают ценность от платформы

## Exit Criteria

- external integrations работают стабильно
- AI functions доказали ценность на реальных сценариях
- partner flows дают измеримый эффект
- marketplace layer не ломает core operations

---

## Product Workstreams

Roadmap должен вестись не только по горизонтам, но и по постоянным workstreams.

### Workstream A. Core Operations

- bookings
- schedule
- staff workflows
- operational UI
- calendar management

### Workstream B. Client Experience

- Telegram flows
- mobile journey
- self-service actions
- reminders
- visit transparency

### Workstream C. Revenue and Retention

- loyalty
- promotions
- deposits
- client reactivation
- repeat visit mechanics

### Workstream D. Platform and SaaS

- tenants
- billing
- onboarding
- support tooling
- configuration

### Workstream E. Data and Intelligence

- reporting
- dashboards
- KPIs
- predictive signals
- AI assistance

### Workstream F. Trust, Security, Compliance

- RBAC
- audit
- observability
- tenant isolation
- operational resilience

---

## Priority Model

При конфликте приоритетов применяется следующий порядок:

### Priority 1

Функции, влияющие на способность студии ежедневно работать.

Примеры:

- bookings
- schedule
- staff access
- cancellation correctness
- operational visibility

### Priority 2

Функции, напрямую влияющие на деньги и удержание.

Примеры:

- deposits
- payments readiness
- reminders
- loyalty
- no-show controls

### Priority 3

Функции, повышающие управляемость и повторяемость бизнеса.

Примеры:

- analytics
- audit
- standardization
- onboarding tooling

### Priority 4

Функции, делающие платформу масштабируемой для внешних tenant.

Примеры:

- tenant engine
- billing
- white-label
- support console

### Priority 5

Функции ecosystem and expansion.

Примеры:

- marketplace
- external API ecosystem
- advanced AI growth loops

---

## What Must Not Happen

Roadmap прямо запрещает следующие ошибки:

### 1. Premature platformization

Нельзя жертвовать работающим operational core ради ранней красивой SaaS-обёртки.

### 2. Feature sprawl

Нельзя одновременно строить слишком много направлений без доведения core функций до зрелости.

### 3. Cosmetic loyalty

Нельзя внедрять бонусы без связки с реальными retention mechanics.

### 4. AI without operational value

Нельзя внедрять AI-функции только ради тренда.

### 5. Marketplace before control

Нельзя запускать ecosystem layer, пока не стабилизированы bookings, payments, retention и tenant isolation.

---

## Suggested Release Logic

### Release Train A

Operational releases:

- booking improvements
- staff workflows
- fixes for scheduling
- daily operational tools

### Release Train B

Commercial releases:

- loyalty
- promotions
- payment-related improvements
- retention flows

### Release Train C

Platform releases:

- tenant features
- billing
- onboarding
- admin tooling

### Release Train D

Expansion releases:

- APIs
- ecosystem
- marketplace
- AI growth tooling

---

## KPI Framework

Roadmap должен оцениваться не по количеству выпущенных экранов, а по продуктовым результатам.

### Operational KPIs

- booking success rate
- schedule conflict rate
- cancellation rate
- no-show rate
- admin handling time
- staff utilization visibility

### Growth KPIs

- repeat booking rate
- client retention rate
- reminder conversion impact
- reactivation rate
- loyalty usage rate

### Revenue KPIs

- average чек
- visits per client
- revenue per staff
- deposit coverage
- recovered revenue from no-show controls

### SaaS KPIs

- tenant onboarding completion rate
- time-to-first-value for new tenant
- tenant monthly retention
- feature adoption by tenant
- support burden per tenant

### Platform KPIs

- integration usage
- partner activity
- ecosystem revenue share
- AI-assisted action adoption

---

## Dependencies

Ниже перечислены ключевые зависимости roadmap.

### Product Dependencies

- policy clarity for bookings and cancellations
- service catalog normalization
- staff schedule model
- client communication rules
- pricing and deposit policy

### Technical Dependencies

- modular monolith discipline
- reliable booking domain
- audit layer
- event/outbox readiness
- observability baseline
- tenant-aware architecture

### Organizational Dependencies

- единый product ownership
- дисциплина приоритизации
- готовность студии реально использовать систему
- цикл обратной связи от операционного персонала

---

## Risks

### Risk 1. Core instability

Если booking core нестабилен, весь roadmap теряет смысл.

### Risk 2. Too many parallel bets

Если вести одновременно core, loyalty, SaaS and marketplace, продукт начнёт расползаться.

### Risk 3. Weak tenant model

Если multi-tenant будет внедрён поздно и неаккуратно, переработка станет дорогой.

### Risk 4. Low operational adoption

Если сотрудники обходят систему вручную, продуктовые метрики будут искажены.

### Risk 5. Retention features without data discipline

Если история клиента, completed status и коммуникации ненадёжны, CRM и loyalty будут работать плохо.

---

## Mitigation Strategy

- держать booking domain как transactional core
- не открывать новые product layers, пока не закрыты exit criteria текущего горизонта
- строить observability одновременно с функционалом
- использовать operational feedback как главный источник приоритета на ранних этапах
- делать platformization только на базе уже работающих business flows

---

## Suggested Sequencing

Ниже рекомендованная строгая последовательность развития.

### Sequence 1

Operational Core

- clients
- staff
- services
- bookings
- notifications
- admin calendar
- Telegram core

### Sequence 2

Business Control

- audit
- dashboards
- deposits readiness
- policy layer
- schedule intelligence

### Sequence 3

Retention Engine

- loyalty
- reminders
- segmentation
- reactivation
- promotions
- risk controls

### Sequence 4

SaaS Core

- tenants
- tenant policies
- tenant admin
- billing
- onboarding
- white-label

### Sequence 5

Expansion

- API platform
- partner layer
- AI assistants
- ecosystem analytics
- marketplace

---

## Product Definition of Done by Stage

### Studio OS is done when

- ежедневная работа студии проходит через систему
- запись, отмена и перенос контролируются
- мастера и менеджер работают в едином контуре
- клиент может пройти базовый self-service путь

### Growth Engine is done when

- retention mechanisms приносят измеримый эффект
- no-show и cancellation управляются политиками
- есть рабочая loyalty loop
- у руководства есть revenue and retention visibility

### SaaS Platform is done when

- новый tenant можно поднять без ручного вмешательства разработчиков
- данные изолированы
- настройки конфигурируемы
- есть биллинг и support contour

### Beauty Ecosystem is done when

- платформенные интеграции дают ценность
- partner mechanics создают network effects
- AI помогает growth and operations
- revenue comes from more than one layer

---

## Final Product Direction

Итоговое направление Reva Studio:

- сначала стать лучшей операционной системой для собственной студии
- затем стать инструментом роста выручки и удержания
- потом стать стандартизируемой SaaS-платформой для других салонов
- и только потом расшириться в beauty ecosystem с marketplace и AI layers

---

## Executive Summary

Roadmap Reva Studio должен реализовываться не как набор разрозненных функций, а как последовательная эволюция продукта:

1. Operational control
2. Business optimization
3. Retention and revenue expansion
4. SaaS platformization
5. Ecosystem expansion

Главное правило roadmap:

Каждый следующий уровень строится только поверх уже работающего предыдущего уровня.

Именно эта последовательность даёт максимальный шанс превратить Reva Studio из внутреннего инструмента в устойчивый SaaS-продукт и затем в платформу.