# Tenancy Domain

Status: Accepted

Last Updated: 2026-03-23

Owners: Architecture

Related:
- `docs/architecture/0001-system-overview.md`
- `docs/architecture/0002-modular-monolith-strategy.md`
- `docs/architecture/0003-tenancy-model.md`
- `docs/architecture/0004-auth-and-rbac.md`
- `docs/architecture/0006-payments-and-ledger.md`

## TL;DR

Reva Studio использует shared-database, shared-schema multi-tenant модель на старте, где каждая бизнес-сущность, содержащая tenant-scoped данные, обязана иметь `tenant_id`, а каждый запрос приложения обязан проходить через tenant-aware access layer. Для дополнительной защиты на уровне БД применяется PostgreSQL Row-Level Security как defense-in-depth слой, а не как замена корректной фильтрации на уровне приложения. PostgreSQL поддерживает row security policies и явное включение RLS на таблицах через `ALTER TABLE ... ENABLE ROW LEVEL SECURITY`, а отдельные роли могут иметь атрибут `BYPASSRLS`, поэтому архитектура должна проектироваться так, чтобы application role не имела этого обхода. :contentReference[oaicite:0]{index=0}

Ключевые правила:
- tenant isolation обязательна для всех tenant-scoped таблиц и запросов;
- `tenant_id` является обязательной частью доменной модели, а не опциональной меткой;
- tenant boundary проверяется на уровне API, application services, repositories и database policies;
- доступ пользователя определяется не только его identity, но и membership в конкретном tenant;
- cookies и session-boundary не используются как единственный барьер изоляции между разными security scopes на одном host, поскольку OWASP отдельно предупреждает, что разные приложения не рекомендуется размещать на одном host как единственный механизм изоляции, а cookie Path сам по себе не даёт надёжной изоляции; SameSite регулирует отправку cookie в cross-site сценариях, но не заменяет tenant isolation внутри приложения. :contentReference[oaicite:1]{index=1}

## 1. Purpose

Документ определяет доменную модель tenancy для Reva Studio и правила изоляции данных между салонами, филиалами и рабочими пространствами. Здесь tenancy понимается как фундаментальная способность платформы обслуживать несколько независимых business tenants внутри одной системы без утечки данных, пересечения прав и нарушения бизнес-инвариантов. OWASP отдельно выделяет tenant isolation как базовое требование безопасности multi-tenant приложений. :contentReference[oaicite:2]{index=2}

## 2. Scope

Этот документ покрывает:
- модель tenant и membership;
- tenant-scoped сущности;
- propagation tenant context через API и application layer;
- database isolation strategy;
- RLS strategy;
- cross-tenant access rules;
- observability и audit для tenant context;
- правила миграции и тестирования tenancy.

Этот документ не покрывает:
- полный UI/UX дизайн переключения workspace;
- биллинг тарификации по tenant;
- юридическую модель договоров;
- physical sharding strategy на поздних стадиях масштабирования.

## 3. External Facts

Ниже перечислены внешние, подтверждаемые источниками факты, на которые опирается модель:

1. PostgreSQL поддерживает Row-Level Security policies, которые включаются на таблицах и задаются через policies. :contentReference[oaicite:3]{index=3}
2. PostgreSQL роли с атрибутом `BYPASSRLS`, а также superuser, могут обходить RLS-политики, поэтому нельзя считать RLS абсолютной защитой без корректной настройки ролей. :contentReference[oaicite:4]{index=4}
3. OWASP рекомендует обеспечивать tenant isolation и отдельно рассматривает риски cross-tenant access в multi-tenant системах. :contentReference[oaicite:5]{index=5}
4. JWT по RFC 7519 является compact URL-safe форматом для claims между сторонами и может быть подписан или защищён MAC, но сам по себе формат токена не гарантирует правильную авторизацию без корректной серверной проверки claims и контекста. :contentReference[oaicite:6]{index=6}
5. `Set-Cookie` и атрибуты cookie, включая SameSite, регулируют поведение браузера при отправке cookie, но не заменяют application-level authorization. Современные браузеры используют SameSite для ограничения cross-site отправки cookie, а для `SameSite=None` требуется `Secure`. :contentReference[oaicite:7]{index=7}
6. OWASP указывает, что не рекомендуется полагаться на Path-изоляцию cookie для разделения разных приложений или security scopes на одном host. :contentReference[oaicite:8]{index=8}

## 4. Internal Architectural Decisions

Ниже идут внутренние архитектурные решения Reva Studio. Это не внешние факты, а целевые правила проекта.

- На старте используется shared-database, shared-schema tenancy.
- Основная единица изоляции в домене называется `Tenant`.
- Все tenant-scoped записи обязаны содержать `tenant_id`.
- Пользователь может состоять в нескольких tenants через membership-модель.
- Tenant context выбирается явно для каждого запроса.
- RLS используется как defense-in-depth поверх application filtering.
- Cross-tenant aggregates на старте запрещены вне специальных системных сценариев.
- Global entities выделяются отдельно и не смешиваются с tenant-scoped таблицами.
- Все фоновые задачи, webhook processors и интеграции обязаны переносить tenant context явно.

## 5. Tenancy Model

### 5.1 Canonical Tenant Definition

`Tenant` в Reva Studio это изолированное бизнес-пространство, которому принадлежат:
- клиенты;
- сотрудники;
- услуги;
- бронирования;
- бонусные программы;
- платежи;
- настройки;
- уведомления;
- аналитические срезы;
- документы и артефакты домена.

На уровне бизнеса tenant обычно соответствует одному салону или одному логическому бизнес-аккаунту. Если в будущем будет введён режим сети салонов, то сеть рассматривается как отдельный уровень above-tenant grouping, но не заменяет сам tenant.

### 5.2 Shared Database Strategy

На старте используется одна PostgreSQL база и одна основная схема приложения, внутри которой tenant isolation обеспечивается через:
- обязательный `tenant_id` в tenant-scoped таблицах;
- composite indexes с `tenant_id`;
- application-layer filtering;
- RLS policies;
- audit и observability с tenant tagging.

Причина выбора:
- проще эксплуатация;
- ниже стоимость запуска;
- проще миграции и аналитика на ранней стадии;
- быстрее развитие продукта.

Ограничение:
- эта стратегия требует жёсткой дисциплины в query design и тестах.

## 6. Core Domain Objects

### 6.1 Tenant

Минимальный рекомендуемый состав полей:

- `id`
- `slug`
- `display_name`
- `status`
- `timezone`
- `default_currency`
- `country_code`
- `plan_code`
- `created_at`
- `updated_at`
- `archived_at`

Рекомендуемые статусы:
- `active`
- `suspended`
- `archived`

### 6.2 User

`User` представляет identity principal. Пользователь не считается автоматически принадлежащим одному tenant. Принадлежность задаётся через membership.

Минимальный рекомендуемый состав полей:
- `id`
- `login`
- `password_hash`
- `status`
- `created_at`
- `updated_at`

### 6.3 TenantMembership

Связывает user и tenant и определяет его роль внутри tenant.

Минимальный рекомендуемый состав полей:
- `id`
- `tenant_id`
- `user_id`
- `role_code`
- `status`
- `invited_at`
- `joined_at`
- `revoked_at`

Рекомендуемые статусы:
- `invited`
- `active`
- `revoked`

### 6.4 TenantScopedEntity

Любая tenant-scoped сущность обязана:
- хранить `tenant_id`;
- иметь foreign key на `tenants.id`;
- использовать `tenant_id` в уникальных ограничениях там, где идентификатор уникален только внутри tenant.

Примеры:
- `customers`
- `staff_members`
- `services`
- `bookings`
- `payments`
- `loyalty_accounts`
- `notification_templates`
- `analytics_snapshots`

### 6.5 GlobalEntity

Global entities не принадлежат tenant напрямую и используются только там, где данные действительно общие для всей платформы.

Примеры:
- системные справочники валют;
- глобальные feature flags платформы;
- справочник стран;
- внутренние технические таблицы миграций и outbox housekeeping.

Требование:
global entities должны быть явно помечены как global в архитектуре и код-ревью. Нельзя оставлять это на неявное соглашение.

## 7. Isolation Principles

### 7.1 Hard Rule

Никакая операция пользователя не должна возвращать, изменять или агрегировать tenant-scoped данные другого tenant без специально разрешённого системного сценария.

### 7.2 No Implicit Tenant Inference from Client Only

Tenant context не должен определяться только по данным, пришедшим от клиента, без проверки membership. JWT может переносить claims, но сервер обязан сам проверить, что user действительно активен в данном tenant и имеет нужную роль. JWT как формат стандартизован RFC 7519, но авторизация остаётся обязанностью сервера. :contentReference[oaicite:9]{index=9}

### 7.3 Defense in Depth

Tenant isolation обеспечивается одновременно на нескольких слоях:
- transport and identity layer;
- application authorization layer;
- repository/query layer;
- database policy layer;
- observability and audit layer.

### 7.4 No UI-Only Isolation

Скрытие tenant данных на уровне интерфейса не считается мерой изоляции. Реальная изоляция должна обеспечиваться на backend и в базе.

## 8. Identity and Tenant Context

### 8.1 Authentication

Authentication отвечает на вопрос "кто пользователь".

Допустимые carrier mechanisms:
- bearer token;
- secure session cookie;
- service-to-service credentials.

### 8.2 Authorization

Authorization отвечает на вопрос:
- в каком tenant действует пользователь;
- какая роль у него в этом tenant;
- над каким ресурсом он может выполнять действие.

### 8.3 Tenant Context Resolution

Порядок обработки запроса:
1. сервер аутентифицирует principal;
2. извлекает requested tenant context;
3. проверяет активное membership;
4. строит request-scoped authorization context;
5. передаёт его в application services и repositories.

### 8.4 Recommended Context Object

Рекомендуемый request context:

- `actor_id`
- `tenant_id`
- `membership_id`
- `role_code`
- `permissions`
- `request_id`
- `correlation_id`

### 8.5 Token Claims

Если используется JWT, в claims допустимо переносить:
- `sub`
- `iat`
- `exp`
- `jti`
- при необходимости tenant hint

Но tenant hint в токене не считается единственным источником истины. Сервер всё равно обязан проверять membership в БД или в согласованном authorization cache. JWT задаёт структуру claims, но бизнес-достоверность claims определяется приложением. :contentReference[oaicite:10]{index=10}

## 9. Cookie and Session Boundary Rules

Если применяется cookie-based auth:
- cookie обязана быть `HttpOnly`;
- production cookie обязана быть `Secure`;
- `SameSite` выбирается осознанно под UX и CSRF модель;
- при `SameSite=None` обязательно `Secure`. :contentReference[oaicite:11]{index=11}

Важно:
- cookie attributes защищают transport/session behavior, но не заменяют tenant authorization;
- cookie `Path` нельзя считать надёжным механизмом разделения security scopes на одном host, OWASP отдельно предупреждает против такой модели. :contentReference[oaicite:12]{index=12}

Внутреннее правило Reva Studio:
- tenant isolation всегда проверяется на backend независимо от cookie policy.

## 10. Database Design Rules

### 10.1 Mandatory `tenant_id`

Для всех tenant-scoped таблиц:
- `tenant_id UUID NOT NULL`
- foreign key to `tenants(id)`

### 10.2 Composite Uniqueness

Если бизнес-идентификатор уникален только внутри tenant, используется составной unique key.

Примеры:
- `(tenant_id, phone_normalized)` для клиента;
- `(tenant_id, code)` для промокода;
- `(tenant_id, booking_public_id)` для бронирования.

### 10.3 Indexing

Минимум:
- индекс по `tenant_id` на каждой tenant-scoped таблице;
- composite indexes, где `tenant_id` идёт первым, если запросы почти всегда tenant-filtered;
- review больших таблиц под `(tenant_id, created_at)` и `(tenant_id, status, created_at)`.

### 10.4 Foreign Keys

Предпочтительно, чтобы все связи между tenant-scoped таблицами были tenant-consistent. Если `booking` принадлежит tenant, то связанный `payment` обязан принадлежать тому же tenant.

Внутреннее правило:
- cross-tenant foreign key relationships запрещены.

### 10.5 No Nullable Tenant for Scoped Data

Если сущность tenant-scoped, `tenant_id` не должен быть nullable. Nullable tenant делает модель двусмысленной и увеличивает риск ошибок фильтрации.

## 11. Row-Level Security Strategy

PostgreSQL поддерживает RLS как встроенный механизм для ограничения доступа к строкам таблиц и применение policies через `CREATE POLICY`. :contentReference[oaicite:13]{index=13}

### 11.1 Role of RLS in Reva Studio

RLS используется как дополнительный защитный слой:
- против ошибок в query code;
- против accidental full-table scans без tenant predicate;
- для усиления изоляции в read/write операциях.

### 11.2 Non-Goals of RLS

RLS не считается единственным механизмом изоляции, потому что:
- её можно обойти ролями с `BYPASSRLS`;
- она не заменяет бизнесовую авторизацию;
- неправильная application role configuration делает RLS бесполезной. :contentReference[oaicite:14]{index=14}

### 11.3 Required Operational Rules

- application DB role не должна иметь `BYPASSRLS`;
- суперпользователь не используется приложением;
- каждая tenant-scoped таблица проходит review на RLS readiness;
- session tenant context задаётся явно для policy evaluation;
- migration scripts тестируют наличие и корректность policies.

### 11.4 Policy Pattern

Рекомендуемый паттерн:
- приложение устанавливает request-scoped tenant context в session/local setting;
- policy проверяет, что `tenant_id` строки совпадает с tenant context текущего запроса.

Конкретная SQL-реализация фиксируется в отдельном ADR и migration policy spec.

## 12. Application Layer Rules

### 12.1 Repository Contract

Ни один repository для tenant-scoped сущностей не должен иметь публичный метод, который читает или меняет данные без `tenant_id` в контракте.

Плохо:
- `get_booking(id)`

Хорошо:
- `get_booking(tenant_id, booking_id)`

### 12.2 Service Contract

Application services обязаны принимать request context или authorization context, а не только raw user id.

### 12.3 Background Jobs

Любая задача очереди обязана явно содержать:
- `tenant_id`
- `actor_id` если применимо
- `correlation_id`

Запрещено:
- запускать фоновые job handlers, которые заново "угадывают" tenant по косвенным данным.

### 12.4 Integrations and Webhooks

Webhook или внешняя интеграция не должны писать в tenant-scoped данные, пока tenant не определён однозначно через:
- mapping table;
- provider account linkage;
- verified reference object.

## 13. Authorization Model Inside Tenant

### 13.1 Membership-Based Access

Доступ предоставляется через `TenantMembership`.

Базовые роли на старте:
- `owner`
- `admin`
- `manager`
- `staff`
- `viewer`

### 13.2 Permission Evaluation

Рекомендуемый порядок:
1. authentication;
2. membership lookup;
3. membership status check;
4. role to permission mapping;
5. object-level checks;
6. repository call with tenant predicate.

### 13.3 Cross-Tenant Super-Admin

На старте production business path не должен использовать человеческий "global super-admin", который напрямую читает tenant-данные без явного режима elevated access.

Если такой режим вводится для поддержки:
- он должен быть отдельным системным режимом;
- все действия логируются;
- используется explicit reason code;
- действия ограничиваются по времени;
- данные маскируются там, где возможно.

## 14. Domain Boundaries

### 14.1 Tenancy as a Cross-Cutting Domain

Tenancy влияет на все домены:
- bookings;
- customers;
- staff;
- payments;
- loyalty;
- notifications;
- analytics;
- files;
- audit.

### 14.2 Required Tenant Ownership Matrix

Для каждого bounded context должен существовать ownership matrix:
- какая сущность global;
- какая tenant-scoped;
- какой entity root определяет tenant ownership;
- можно ли объект перемещать между tenants.

### 14.3 Object Transfer Between Tenants

Общее правило:
- перенос существующего tenant-scoped объекта между tenants запрещён.

Вместо этого:
- создаётся новый объект в другом tenant;
- перенос выполняется через controlled migration/import workflow;
- old object остаётся в истории.

Это уменьшает риск нарушения ссылочной целостности и аудита.

## 15. Observability and Audit

### 15.1 Structured Logging

Все tenant-scoped операции обязаны логировать:
- `tenant_id`
- `actor_id`
- `request_id`
- `correlation_id`
- `membership_id` если есть
- `resource_type`
- `resource_id`

### 15.2 Audit Log

Для критичных операций аудит обязан фиксировать:
- кто выполнил действие;
- в каком tenant;
- над каким объектом;
- какое было основание;
- что именно изменилось;
- когда это произошло.

### 15.3 Metrics

Рекомендуемые tenancy-метрики:
- denied cross-tenant access attempts;
- missing tenant context errors;
- RLS policy violations if surfaced;
- tenant-scoped query latency;
- per-tenant workload distribution;
- background jobs without tenant context.

## 16. Testing Requirements

### 16.1 Unit Tests

Покрыть:
- tenant context resolution;
- membership authorization;
- role mapping;
- repository contract validation.

### 16.2 Integration Tests

Покрыть:
- невозможность прочитать объект другого tenant;
- невозможность изменить объект другого tenant;
- webhook with wrong tenant mapping;
- background job with missing tenant context;
- RLS enforcement under application role.

### 16.3 Security Tests

Покрыть:
- IDOR-style access attempts across tenant boundary;
- crafted token with чужим tenant hint;
- missing tenant filter regressions;
- raw SQL path bypass attempts.

OWASP отдельно подчёркивает важность защиты от cross-tenant access и tenant isolation failures в multi-tenant приложениях. :contentReference[oaicite:15]{index=15}

### 16.4 Migration Tests

Каждая новая tenant-scoped таблица обязана проверяться на:
- наличие `tenant_id`;
- индекс по `tenant_id`;
- foreign key;
- repository methods with tenant-aware signatures;
- RLS applicability, если таблица входит в RLS scope.

## 17. Operational Rules

### 17.1 Safe Defaults

По умолчанию любая новая бизнес-таблица считается tenant-scoped, пока архитектурно не доказано обратное.

### 17.2 No Raw SQL Without Tenant Review

Любой raw SQL, касающийся tenant-scoped таблиц, проходит отдельный review на наличие tenant predicate и совместимость с RLS.

### 17.3 No Shared Caches Without Tenant Dimension

Кэш-ключи для tenant-scoped данных обязаны включать `tenant_id`.

Плохо:
- `customer:{id}`

Хорошо:
- `tenant:{tenant_id}:customer:{id}`

### 17.4 No Analytics Rollups Without Explicit Scope

Агрегации по нескольким tenants допускаются только в системных аналитических пайплайнах с явной пометкой global scope.

## 18. Migration Path

### Phase 1
Ввести `tenants`, `tenant_memberships`, `tenant_id` и request context propagation во все ключевые домены.

### Phase 2
Привести repositories и services к tenant-aware контрактам.

### Phase 3
Включить RLS на критичных tenant-scoped таблицах как defense-in-depth.

### Phase 4
Добавить automated tenancy regression suite.

### Phase 5
Оценить необходимость schema-per-tenant или shard evolution только после достижения реальных пределов shared-schema модели.

## 19. Rejected Alternatives

### Alternative A. Single-Tenant Architecture

Причина отказа:
- не соответствует целевой SaaS-модели Reva Studio;
- усложняет рост до multi-salon платформы.

### Alternative B. Separate Database Per Tenant on Day 1

Причина отказа:
- повышает операционную сложность;
- замедляет развитие продукта на ранней стадии;
- усложняет единые миграции и аналитические процессы.

Не могу подтвердить, что этот вариант никогда не понадобится в будущем. Это зависит от фактического масштаба, требований по compliance и объёма tenant-данных.

### Alternative C. Isolation Only in UI

Причина отказа:
- не обеспечивает реальную безопасность;
- не защищает API и фоновые процессы;
- противоречит базовым принципам secure multi-tenant design. :contentReference[oaicite:16]{index=16}

## 20. Final Rule Set

Обязательные правила проекта:

1. Любая tenant-scoped таблица обязана иметь `tenant_id`.
2. Любой tenant-scoped repository method обязан принимать tenant context.
3. Любой запрос к tenant-scoped данным обязан фильтроваться по tenant.
4. RLS применяется как дополнительный защитный слой, а не как единственный.
5. Application DB role не должна иметь `BYPASSRLS`. :contentReference[oaicite:17]{index=17}
6. Cookie policy не считается tenant isolation strategy. :contentReference[oaicite:18]{index=18}
7. JWT claims не заменяют membership verification. :contentReference[oaicite:19]{index=19}
8. Background jobs и integrations обязаны переносить `tenant_id` явно.
9. Cross-tenant access без специального системного режима запрещён.
10. Любая новая tenant-scoped сущность обязана пройти tenancy review до merge.

## 21. References

1. PostgreSQL Documentation, Row Security Policies
   https://www.postgresql.org/docs/current/ddl-rowsecurity.html

2. PostgreSQL Documentation, CREATE POLICY
   https://www.postgresql.org/docs/current/sql-createpolicy.html

3. PostgreSQL Documentation, Role Attributes
   https://www.postgresql.org/docs/current/role-attributes.html

4. PostgreSQL Documentation, Predefined Roles
   https://www.postgresql.org/docs/current/predefined-roles.html

5. OWASP Cheat Sheet Series, Multi-Tenant Security Cheat Sheet
   https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html

6. RFC 7519, JSON Web Token
   https://www.rfc-editor.org/rfc/rfc7519.html

7. MDN Web Docs, Set-Cookie
   https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie

8. MDN Web Docs, Using HTTP cookies
   https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Cookies

9. MDN Web Docs, Set-Cookie, Russian translation
   https://developer.mozilla.org/ru/docs/Web/HTTP/Reference/Headers/Set-Cookie

10. OWASP Cheat Sheet Series, Session Management Cheat Sheet
    https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

## 22. Source Notes

Подтверждённые внешними источниками тезисы:
- PostgreSQL поддерживает RLS и policies;
- отдельные роли могут обходить RLS через `BYPASSRLS`;
- OWASP рекомендует обеспечивать tenant isolation и не полагаться на cookie path isolation;
- JWT это формат claims, а не готовая модель авторизации;
- SameSite и Secure влияют на cookie transport behavior.

Внутренние решения Reva Studio:
- выбор shared-schema tenancy на старте;
- обязательность `tenant_id` во всех tenant-scoped таблицах;
- membership-based access model;
- запрет cross-tenant transfers;
- конкретные роли и фазовый migration path.

Эти внутренние решения являются архитектурными правилами проекта, а не внешними фактами.