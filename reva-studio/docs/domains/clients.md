# Clients Domain

## Document Status

Accepted

## Version

1.0

## Last Updated

2026-03-23

## Owners

Architecture
Backend
Product
CRM

## Purpose

Этот документ фиксирует промышленную модель домена клиентов для Reva Studio.

Домен `clients` отвечает за:

- учёт клиентских профилей
- контактные данные и предпочтения
- согласия на коммуникации
- клиентские теги и сегменты
- историю статусов клиента
- привязку к бронированиям, лояльности, уведомлениям и аналитике

Домен не отвечает за:

- расписание мастеров
- каталог услуг
- финансовый расчёт платежей
- балансы лояльности как источник истины
- доставку уведомлений
- аутентификацию сотрудников

Граница домена должна быть явной. В DDD bounded context нужен именно для того, чтобы разделять модели и делать их отношения явными, а не смешивать всё в один общий объект. :contentReference[oaicite:1]{index=1}

## Goals

Домен клиентов должен обеспечивать:

- единый канонический профиль клиента в пределах tenant
- предсказуемую работу с персональными данными
- чёткое разделение PII и операционных данных
- расширяемость под CRM, loyalty, promotions и analytics
- безопасную работу с согласиями на коммуникации
- удобную интеграцию с booking, loyalty, notifications и admin

## Architectural Position

`clients` является отдельным bounded context внутри модульного монолита Reva Studio.

Он взаимодействует с:

- `identity` или `auth`, если у клиента есть вход в систему
- `bookings`
- `loyalty`
- `notifications`
- `analytics`
- `payments`
- `admin`

Основной принцип:

- домен клиентов владеет профилем клиента
- другие домены не изменяют профиль напрямую
- все изменения клиентского профиля проходят через application-команды домена `clients`

Это соответствует bounded context подходу: у каждого контекста должна быть собственная модель и собственные границы изменений. :contentReference[oaicite:2]{index=2}

## Business Responsibilities

Домен клиентов решает следующие бизнес-задачи:

1. Хранить и изменять основную карточку клиента.
2. Хранить контактные каналы клиента.
3. Хранить согласия на SMS, email, push и мессенджеры.
4. Поддерживать статус клиента внутри tenant.
5. Поддерживать CRM-метки и сегменты.
6. Предоставлять безопасный read-model для интерфейсов администратора и клиента.
7. Публиковать доменные события для зависимых модулей.
8. Поддерживать удаление, деактивацию и анонимизацию клиентских данных по политике платформы.

## Privacy and Data Handling Principles

Так как домен клиентов работает с персональными данными, он должен строиться по принципам purpose limitation, data minimisation, accuracy и storage limitation. Эти принципы прямо перечислены в GDPR Article 5. :contentReference[oaicite:3]{index=3}

Из этого следуют обязательные архитектурные правила:

- хранить только данные, которые действительно нужны сервису
- разделять обязательные поля и опциональные CRM-поля
- не использовать контактные данные клиента вне заявленных бизнес-целей
- не дублировать PII по другим доменам без необходимости
- фиксировать согласия и отзыв согласий
- поддерживать анонимизацию или ограничение хранения данных по политике платформы

OWASP отдельно рекомендует проектировать системы так, чтобы снижать риски для приватности пользователей и минимизировать ненужное раскрытие данных. :contentReference[oaicite:4]{index=4}

## Tenant Model

Reva Studio проектируется как tenant-aware платформа.

Следовательно:

- клиент существует внутри конкретного `tenant_id`
- один и тот же человек в разных tenant рассматривается как разные клиентские записи, если не внедрён отдельный cross-tenant identity layer
- все уникальные ограничения домена клиентов tenant-scoped
- любой запрос к клиенту обязан фильтроваться по `tenant_id`

## Ubiquitous Language

### Client

Клиент салона внутри одного tenant.

### Client Profile

Каноническая карточка клиента с идентификатором, базовыми атрибутами, статусом и контактами.

### Contact Method

Подтверждённый или неподтверждённый канал связи клиента.

### Consent

Зафиксированное разрешение или отказ на конкретный тип коммуникации.

### Tag

Ярлык для ручной CRM-классификации клиента.

### Segment

Вычисляемая или вручную назначенная группа клиентов.

### Lifecycle Status

Бизнес-статус клиента внутри tenant.

Примеры:

- lead
- active
- returning
- vip
- inactive
- blocked
- archived

### Preferred Master

Предпочитаемый мастер клиента.

### Client Note

Служебная заметка сотрудника о клиенте.

## Aggregate Design

### Primary Aggregate: Client

`Client` является главным aggregate root домена.

Он управляет:

- основным профилем
- статусом
- контактами
- согласиями
- тегами
- предпочтениями
- заметками
- метаданными CRM

Почему именно aggregate root:

- изменения клиентского профиля должны быть согласованными
- инварианты по PII, consent и статусам должны соблюдаться в одной транзакционной границе
- внешние модули должны работать через публичные команды, а не через прямое изменение таблиц

## Core Entities

### Client

Основная сущность домена.

Поля:

- `id`
- `tenant_id`
- `external_ref` nullable
- `first_name`
- `last_name` nullable
- `middle_name` nullable
- `display_name`
- `birth_date` nullable
- `gender` nullable
- `status`
- `source_channel`
- `preferred_language` nullable
- `preferred_master_id` nullable
- `created_at`
- `updated_at`
- `archived_at` nullable
- `version`

Замечания:

- `display_name` хранится отдельно для быстрого чтения и поиска
- `external_ref` нужен для интеграций
- `version` нужен для optimistic concurrency control

### ClientContact

Канал связи клиента.

Поля:

- `id`
- `client_id`
- `tenant_id`
- `contact_type`
- `contact_value`
- `normalized_value`
- `is_primary`
- `is_verified`
- `verified_at` nullable
- `created_at`
- `updated_at`

Поддерживаемые типы:

- `phone`
- `email`
- `telegram`
- `whatsapp`
- `instagram`
- `other`

### ClientConsent

Согласие на коммуникацию.

Поля:

- `id`
- `client_id`
- `tenant_id`
- `channel`
- `purpose`
- `status`
- `granted_at` nullable
- `revoked_at` nullable
- `source`
- `proof_ref` nullable
- `created_by_type`
- `created_by_id` nullable
- `created_at`
- `updated_at`

Поддерживаемые `channel`:

- `sms`
- `email`
- `push`
- `telegram`
- `whatsapp`

Поддерживаемые `purpose`:

- `marketing`
- `transactional`
- `reminder`
- `reactivation`
- `loyalty`
- `feedback`

Поддерживаемые `status`:

- `granted`
- `revoked`
- `unknown`

### ClientTag

Ручной тег CRM.

Поля:

- `id`
- `tenant_id`
- `name`
- `color` nullable
- `description` nullable
- `is_system`
- `created_at`
- `updated_at`

### ClientTagAssignment

Связь клиента и тега.

Поля:

- `id`
- `tenant_id`
- `client_id`
- `tag_id`
- `assigned_by`
- `assigned_at`

### ClientNote

Служебная заметка по клиенту.

Поля:

- `id`
- `tenant_id`
- `client_id`
- `author_staff_id`
- `note_type`
- `body`
- `is_pinned`
- `created_at`
- `updated_at`

### ClientSegment

Определение сегмента.

Поля:

- `id`
- `tenant_id`
- `name`
- `code`
- `description` nullable
- `segment_type`
- `definition_json`
- `is_dynamic`
- `created_at`
- `updated_at`

### ClientSegmentMembership

Материализованная принадлежность клиента сегменту.

Поля:

- `id`
- `tenant_id`
- `client_id`
- `segment_id`
- `source`
- `computed_at`

## Value Objects

### PersonalName

Содержит:

- `first_name`
- `last_name`
- `middle_name`

### ContactValue

Содержит:

- `raw`
- `normalized`
- `type`

### CommunicationPreference

Содержит:

- `preferred_language`
- `preferred_contact_channel`
- `quiet_hours` nullable

### AcquisitionSource

Содержит:

- `channel`
- `campaign` nullable
- `referrer` nullable

## Invariants

Ниже перечислены обязательные инварианты домена:

1. Клиент принадлежит ровно одному tenant.
2. В пределах tenant клиентский aggregate изменяется только через домен `clients`.
3. У клиента может быть не более одного primary contact для каждого `contact_type`.
4. `normalized_value` должен быть нормализован по правилам типа контакта.
5. Маркетинговая коммуникация запрещена без актуального consent для нужного канала и purpose.
6. Архивированный клиент не может получать новые маркетинговые назначения.
7. Удаление клиента физически не должно выполняться без специальных административных процедур и политики retention.
8. Записи согласий должны быть аудируемыми.
9. Все read-модели обязаны фильтроваться по `tenant_id`.
10. Любое изменение PII должно оставлять audit trail.

Требование к auditability и управляемым логам согласуется с OWASP guidance по logging и privacy-защите. :contentReference[oaicite:5]{index=5}

## Client Lifecycle

Жизненный цикл клиента:

1. lead
2. active
3. returning
4. vip
5. inactive
6. blocked
7. archived

Описание:

### lead

Клиент создан, но ещё не завершил первую услугу.

### active

Клиент активен и недавно взаимодействовал с салоном.

### returning

Клиент имеет повторные визиты.

### vip

Клиент переведён в привилегированный сегмент по правилам бизнеса.

### inactive

Клиент давно не проявлял активности.

### blocked

Операционное ограничение. Например, при системных или бизнес-конфликтах.

### archived

Клиент выведен из активного оборота. Используется для soft-delete или завершения хранения в активной CRM-модели.

## Identity and Identifiers

Для всех основных сущностей должны использоваться UUID-идентификаторы. RFC 9562 определяет UUID как 128-битный универсальный идентификатор и является актуальной спецификацией UUID. :contentReference[oaicite:6]{index=6}

Рекомендуемая политика:

- внутренние ID: UUID
- внешние публичные ссылки: UUID или отдельные opaque-id
- человекочитаемые номера клиента не должны быть первичным ключом

## PII Classification

Для промышленной системы домен клиентов обязан явно разделять PII и неперсональные данные.

### Sensitive or regulated data inside this domain

- имя
- фамилия
- дата рождения
- телефон
- email
- username в мессенджере
- история согласий
- заметки сотрудников, если содержат персональные сведения

### Operational non-PII or low-sensitivity references

- внутренний UUID клиента
- tenant-scoped статусы
- системные теги
- агрегированные флаги сегментации без лишнего раскрытия PII
- внутренние служебные correlation id

Принцип: другие домены получают минимум данных, нужный для выполнения их задачи, а не весь профиль клиента. Это следует из data minimisation и purpose limitation. :contentReference[oaicite:7]{index=7}

## Storage Rules

### Canonical storage

Канонический профиль клиента хранится только в домене `clients`.

### Foreign references only

Другие домены хранят только ссылки:

- `client_id`
- `tenant_id`
- при необходимости денормализованный `display_name` в read-моделях

### No uncontrolled duplication

Запрещено бесконтрольно дублировать:

- телефон
- email
- дату рождения
- consent-статусы

в `bookings`, `payments`, `notifications`, `loyalty` как источник истины.

## Contacts Model

Контакты клиента хранятся отдельно от основной сущности.

Причины:

- у клиента может быть несколько каналов
- верификация идёт по каждому каналу отдельно
- consent относится к каналу и цели, а не ко всему клиенту целиком
- можно безопасно отключать отдельный контакт без разрушения профиля

### Normalization rules

#### phone

- хранить нормализованный формат отдельно
- raw-значение не использовать для поиска

#### email

- нормализовать регистр и пробелы
- валидировать синтаксис до сохранения

#### messenger handles

- хранить raw и normalized отдельно, если есть преобразование

## Consent Model

Consent хранится как самостоятельная сущность, а не как один boolean-флаг у клиента.

Причины:

- согласие зависит от канала
- согласие зависит от цели
- нужен журнал выдачи и отзыва
- требуется доказуемость происхождения consent

### Consent sources

- self_service
- admin
- imported
- booking_form
- campaign_form
- api

### Consent rules

1. `transactional` коммуникации и `marketing` коммуникации разделяются.
2. Отзыв consent не удаляет историю, а меняет статус.
3. История consent должна быть восстановима.
4. Система обязана быстро отвечать на вопрос: можно ли сейчас отправить сообщение этому клиенту по данному каналу для данной цели.

OWASP User Privacy Protection Cheat Sheet поддерживает подход с минимизацией лишних данных и аккуратным обращением с пользовательской приватностью. :contentReference[oaicite:8]{index=8}

## Notes and Internal Staff Data

`ClientNote` предназначен только для внутреннего использования авторизованным персоналом.

Требования:

- заметки не должны попадать в клиентский публичный API
- доступ к заметкам ограничивается ролями
- чувствительные внутренние заметки должны маркироваться
- любые экспорты клиентских данных должны отдельно решать, включать ли заметки

## Segmentation Model

Поддерживаются два типа сегментации:

### Static segmentation

Сегмент задаётся вручную.

Примеры:

- VIP
- problematic
- influencer
- bridal_clients

### Dynamic segmentation

Сегмент вычисляется автоматически.

Примеры:

- no bookings in 90 days
- spent more than threshold
- first visit not completed
- birthday this week
- no marketing consent on any channel

### Design rule

Определение сегмента хранится отдельно от membership.

Это позволяет:

- пересчитывать сегменты
- кешировать membership
- не загрязнять aggregate клиента тяжёлыми аналитическими правилами

## Search and Matching

Домен клиентов должен поддерживать:

- поиск по имени
- поиск по телефону
- поиск по email
- поиск по тегам
- поиск по статусу
- поиск по мастеру
- поиск по сегменту

### Deduplication support

Система должна поддерживать кандидатный поиск дублей по:

- нормализованному телефону
- email
- похожему имени
- одинаковой дате рождения при наличии

Но автоматическое слияние клиентов без явной подтверждённой логики не должно быть дефолтным поведением. Не могу подтвердить единственный универсально правильный алгоритм слияния без дополнительного бизнес-контекста.

## Domain Events

Домен публикует события:

- `client.created`
- `client.updated`
- `client.archived`
- `client.status.changed`
- `client.contact.added`
- `client.contact.verified`
- `client.contact.removed`
- `client.consent.granted`
- `client.consent.revoked`
- `client.tag.assigned`
- `client.tag.removed`
- `client.segment.entered`
- `client.segment.left`
- `client.note.created`
- `client.note.updated`

События должны нести минимум необходимых данных.

Рекомендуемый payload:

- `event_id`
- `event_type`
- `occurred_at`
- `tenant_id`
- `client_id`
- `correlation_id`
- `causation_id`
- business payload без лишней PII

## Commands

Основные команды домена:

- `CreateClient`
- `UpdateClientProfile`
- `ArchiveClient`
- `BlockClient`
- `UnblockClient`
- `AddClientContact`
- `VerifyClientContact`
- `RemoveClientContact`
- `GrantClientConsent`
- `RevokeClientConsent`
- `AssignClientTag`
- `RemoveClientTag`
- `AddClientNote`
- `UpdateClientNote`
- `RebuildClientSegments`
- `MergeClients` optional, protected
- `AnonymizeClient` protected

## Queries

Основные query use cases:

- `GetClientById`
- `GetClientProfile`
- `GetClientContacts`
- `GetClientConsents`
- `GetClientTags`
- `GetClientSegments`
- `GetClientNotes`
- `SearchClients`
- `GetClientTimeline`
- `GetClientSummaryForBooking`
- `GetClientSummaryForLoyalty`
- `GetClientSummaryForNotifications`

## Public Read Models

### ClientSummaryReadModel

Поля:

- `client_id`
- `tenant_id`
- `display_name`
- `primary_phone` nullable
- `primary_email` nullable
- `status`
- `tags`
- `segment_codes`
- `preferred_master_id` nullable
- `last_booking_at` nullable
- `created_at`

### ClientProfileReadModel

Поля:

- `client_id`
- `display_name`
- `personal_name`
- `contacts`
- `consents`
- `status`
- `notes_count`
- `segments`
- `preferred_language`
- `preferred_master_id`
- `birth_date` nullable
- `timeline_preview`

### ClientNotificationEligibilityReadModel

Поля:

- `client_id`
- `channel`
- `purpose`
- `is_allowed`
- `reason_code`
- `evaluated_at`

## API Surface

### Admin API

#### GET /api/v1/admin/clients

Поддерживает фильтры:

- `q`
- `status`
- `tag`
- `segment`
- `preferred_master_id`
- `created_from`
- `created_to`

#### POST /api/v1/admin/clients

Создаёт клиента.

#### GET /api/v1/admin/clients/{client_id}

Возвращает полную карточку клиента.

#### PATCH /api/v1/admin/clients/{client_id}

Обновляет профиль клиента.

#### POST /api/v1/admin/clients/{client_id}/contacts

Добавляет контакт.

#### POST /api/v1/admin/clients/{client_id}/consents/grant

Выдаёт consent.

#### POST /api/v1/admin/clients/{client_id}/consents/revoke

Отзывает consent.

#### POST /api/v1/admin/clients/{client_id}/tags/{tag_id}

Назначает тег.

#### DELETE /api/v1/admin/clients/{client_id}/tags/{tag_id}

Удаляет тег.

#### POST /api/v1/admin/clients/{client_id}/archive

Архивирует клиента.

### Client API

Если у клиента есть self-service кабинет:

#### GET /api/v1/me/profile

Возвращает клиентский профиль в безопасном виде.

#### PATCH /api/v1/me/profile

Разрешает обновление ограниченного набора полей.

#### GET /api/v1/me/consents

Возвращает текущие consent-статусы.

#### POST /api/v1/me/consents

Позволяет изменить собственные consent-настройки.

## Security Requirements

### Authentication

Доступ к клиентским данным должен быть защищён аутентификацией. OWASP Authentication Cheat Sheet описывает authentication как процесс подтверждения того, кем является субъект. :contentReference[oaicite:9]{index=9}

### Authorization

RBAC обязателен.

Правила:

- клиент видит только себя
- staff видит только клиентов своего tenant
- manager получает расширенный доступ
- заметки и ручные сегменты доступны не всем ролям
- операции merge, archive, anonymize и export должны иметь отдельные permissions

### Auditability

Все операции изменения клиента должны оставлять audit trail:

- кто изменил
- когда изменил
- что изменилось
- correlation id
- tenant_id
- target client_id

### Privacy by default

По умолчанию:

- списки не возвращают лишние PII
- search endpoints не раскрывают скрытые поля
- события не разносят ненужные персональные данные
- read-модели должны быть role-aware

Это согласуется с privacy guidance OWASP и GDPR Article 5 principles. :contentReference[oaicite:10]{index=10}

## Data Retention and Deletion

Обязательные стратегии:

- soft-delete через `archived_at`
- отдельная команда анонимизации
- хранение истории consent и audit по retention policy
- физическое удаление только по специальной процедуре

Не могу подтвердить конкретный срок хранения без отдельной юридической политики и юрисдикции проекта.

## Integration Contracts

### With Bookings

`bookings` читает:

- `client_id`
- `display_name`
- primary contact summary
- notification eligibility summary

`bookings` не владеет профилем клиента.

### With Loyalty

`loyalty` использует:

- `client_id`
- `tenant_id`
- безопасный summary клиента
- segment hints при необходимости

### With Notifications

`notifications` не хранит consent как источник истины.
Он должен получать eligibility result из `clients` или из согласованной read-модели.

### With Analytics

`analytics` потребляет доменные события и обезличенные или минимизированные read-модели там, где это возможно.

## Recommended Module Structure

```text
backend/modules/clients/
├── domain/
│   ├── entities/
│   ├── value_objects/
│   ├── services/
│   ├── events/
│   ├── policies/
│   ├── repositories/
│   └── exceptions/
├── application/
│   ├── commands/
│   ├── queries/
│   ├── dto/
│   ├── handlers/
│   └── validators/
├── infrastructure/
│   ├── persistence/
│   ├── projections/
│   ├── mappers/
│   ├── outbox/
│   └── search/
├── api/
│   ├── admin/
│   └── client/
└── tests/
    ├── unit/
    ├── integration/
    └── contract/