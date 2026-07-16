ADR 0003: Tenancy Model
Status

Accepted

Date

2026-03-22

Context

Reva Studio проектируется как SaaS-платформа для beauty-бизнеса с дальнейшим масштабированием на множество салонов, команд и конечных клиентов. Для такой системы tenancy model определяет:

границу изоляции данных между салонами;
модель масштабирования приложения и базы данных;
стоимость эксплуатации;
сложность онбординга новых tenants;
требования к безопасности, авторизации, аудиту и аналитике.

Microsoft определяет multitenancy как архитектурный подход, в котором несколько tenants используют общую платформу, при этом решение должно учитывать изоляцию, масштабируемость, эксплуатацию и стоимость. Также Microsoft отдельно подчёркивает, что tenancy models нужно оценивать через trade-offs между изоляцией, сложностью, масштабированием и операционными издержками.

AWS в guidance по tenant isolation указывает, что для SaaS-систем ключевым требованием является явная стратегия isolation, которая должна быть системной и проходить через все слои архитектуры, а не только через один компонент.

OWASP для multi-tenant приложений отдельно выделяет риск cross-tenant access и рекомендует строить защиту так, чтобы исключить утечки между tenants на уровне проектирования, авторизации и изоляции данных.

Decision

Для Reva Studio принимается модель:

shared application;
shared database;
shared schema;
logical tenant isolation через обязательный tenant_id во всех tenant-scoped сущностях;
enforcement tenant boundaries на двух уровнях:
application layer;
database layer.

Базовое архитектурное решение:

Каждый business tenant представляет собой отдельный салон или организацию.
Все tenant-scoped данные хранятся в общих таблицах, но каждая строка обязана содержать tenant_id.
Каждый запрос приложения обязан выполняться в tenant context.
Доступ к данным tenant ограничивается:
обязательной фильтрацией по tenant_id в application services и repositories;
Row Level Security в PostgreSQL для критичных таблиц.
Глобальные системные сущности отделяются от tenant-scoped сущностей.
Сотрудники, услуги, записи, бонусы, акции, платежи, уведомления и аналитика относятся к tenant-scoped данным, если явно не указано иное.
Переход к более сильной изоляции в будущем допускается для selected tenants через tiered tenancy model без разрушения доменной модели.
Chosen Model
1. Tenant definition

Tenant в Reva Studio это отдельная бизнес-единица, обычно салон, сеть салонов или партнёрская организация.

Tenant обладает собственными:

сотрудниками;
клиентами;
каталогом услуг;
расписанием;
бонусной логикой;
маркетинговыми кампаниями;
финансовой и операционной аналитикой;
настройками бренда и политики доступа.
2. Isolation model

Выбран pooled model на уровне приложения и данных:

одно приложение обслуживает много tenants;
одна база данных обслуживает много tenants;
tenant isolation обеспечивается логически.

Такой подход обычно даёт лучшую экономику, более простой rollout изменений и быстрый onboarding, но требует жёсткой дисциплины tenant isolation. Это соответствует описанным trade-offs tenancy models у Microsoft и AWS.

3. Database model

Для tenant-scoped таблиц используется единый шаблон:

id
tenant_id
created_at
updated_at
created_by
updated_by
при необходимости deleted_at

Примеры tenant-scoped таблиц:

staff
clients
services
service_categories
bookings
booking_slots
payments
loyalty_accounts
loyalty_transactions
promotions
notifications
audit_events
tenant_settings
4. Security model

Tenant isolation считается не только feature, но и security boundary.

Поэтому вводятся обязательные правила:

никакой repository или query service не имеет права читать tenant-scoped данные без tenant context;
super-admin доступ отделён от tenant admin доступа;
все API endpoints обязаны проходить authorization check;
любые batch jobs, integrations и background workers обязаны явно нести tenant context;
любые exports, reports, caches, search indexes и AI-contexts обязаны учитывать tenant boundary.

OWASP прямо рекомендует для authorization применять least privilege и deny by default, а для multi-tenant security предотвращать cross-tenant exposure как первичный риск.

Rationale
Почему не database-per-tenant

Модель database-per-tenant даёт более сильную физическую изоляцию, но резко увеличивает стоимость эксплуатации, сложность миграций, мониторинга, бэкапов, observability и массовых обновлений. Для ранней и средней стадии SaaS-платформы Reva Studio это создаёт лишнюю операционную нагрузку. Microsoft и AWS обе указывают, что выбор tenancy model всегда является компромиссом между уровнем isolation и operational complexity.

Почему не schema-per-tenant

Schema-per-tenant частично улучшает организационную изоляцию, но усложняет миграции, управление индексами, cross-tenant reporting, DevOps-операции и масштабирование числа tenants. Для продукта, который должен быстро расти и стандартизировать бизнес-логику across tenants, shared schema с жёстким tenant_id даёт лучшую управляемость.

Почему выбран shared schema plus strong isolation

Этот подход:

проще в разработке и сопровождении;
лучше подходит для централизованных миграций;
удобнее для общей аналитики платформы;
позволяет дешевле масштабироваться на сотни и тысячи tenants;
совместим с сильной защитой через authorization и PostgreSQL RLS.

PostgreSQL подтверждает, что Row Level Security позволяет определять политики доступа к строкам таблицы и применять их автоматически при запросах.

Isolation Rules
1. Tenant context is mandatory

Каждый request, command, job или integration call обязан иметь один из источников tenant context:

JWT claim;
internal service token claim;
signed background job payload;
system command with explicit tenant assignment.

Если tenant context отсутствует, операция должна быть отклонена.

2. Tenant-scoped tables must contain tenant_id

Любая таблица, содержащая данные tenant, обязана иметь tenant_id типа UUID.

Исключения допускаются только для truly global tables, например:

countries
currencies
feature_flags_catalog
system_roles_catalog
plan_catalog
3. Composite uniqueness must be tenant-aware

Уникальные ограничения строятся с учётом tenant_id.

Примеры:

unique (tenant_id, phone)
unique (tenant_id, slug)
unique (tenant_id, staff_code)
unique (tenant_id, external_id)

Это исключает ложные конфликты между tenants.

4. All tenant queries must be scoped

Любой SQL, ORM query, repository method или read model обязаны включать tenant filtering, если сущность tenant-scoped.

Запрещено:

читать tenant-scoped таблицы без tenant_id;
строить generic admin endpoints без tenant-boundary rules;
использовать unsafe joins, способные объединять данные разных tenants без явного контроля.
5. Database enforcement via PostgreSQL RLS

Для критичных таблиц включается Row Level Security.

Базовый принцип:

приложение устанавливает session-level tenant context;
RLS policy разрешает доступ только к строкам текущего tenant.

PostgreSQL documentation подтверждает, что RLS включается на таблице и управляется через policies, которые ограничивают видимость и изменение строк.

6. Administrative bypass is exceptional

RLS bypass и кросс-tenant доступ не должны быть нормальным режимом работы.

PostgreSQL отдельно документирует, что некоторые роли могут обходить RLS только при специальных правах, и это должно рассматриваться как исключительный административный режим, а не обычный путь чтения данных.

7. Views and derived access paths must stay secure

Если для tenant access используются database views, они должны проектироваться так, чтобы не ослаблять row-level protection.

PostgreSQL documentation указывает, что для безопасного использования view в сценариях row-level protection может требоваться security_barrier.

Domain Classification
Global entities

Глобальные сущности не принадлежат одному tenant и могут использоваться всей платформой:

plan catalog;
feature definitions;
country and currency catalogs;
system policy templates;
platform configuration metadata.
Tenant-scoped entities

Сущности, принадлежащие конкретному tenant:

staff;
clients;
services;
bookings;
payments;
loyalty accounts;
loyalty transactions;
promotions;
subscriptions;
marketing campaigns;
tenant branding;
tenant integrations;
tenant analytics snapshots;
tenant audit trail.
User identity versus tenant membership

Один и тот же actor теоретически может существовать в нескольких tenants, но membership хранится отдельно.

Рекомендуемая модель:

users как platform identity;
tenant_memberships как связь user-to-tenant;
roles и permissions назначаются через membership scope.

Это упрощает B2B-сценарии, франшизы и управляющих, работающих в нескольких салонах.

Request Flow

Нормальный flow tenant-aware запроса:

Клиент проходит authentication.
Система определяет identity и membership.
Из токена или membership-resolver выбирается active tenant.
Authorization проверяет права внутри выбранного tenant.
Application layer передаёт tenant context в use case.
Repository layer формирует tenant-scoped запрос.
Database layer дополнительно применяет RLS policy.
Audit trail фиксирует actor, tenant, action, resource и результат.

Этот многослойный подход соответствует рекомендациям OWASP по robust authorization и multi-tenant security, а также общему isolation mindset AWS.

Operational Consequences
Positive consequences
низкая стоимость онбординга нового tenant;
единый deployment pipeline;
единые миграции схемы;
проще централизованный observability stack;
проще общая продуктовая эволюция;
проще запуск новых модулей SaaS.
Negative consequences
повышенные требования к качеству authorization;
высокий риск cross-tenant leakage при ошибках разработки;
необходимость tenant-aware тестирования;
необходимость обязательного аудита всех data access paths;
сложнее соответствие требованиям клиентов, которым нужна физическая изоляция.
Mitigations

Для компенсации рисков вводятся обязательные меры:

tenant_id в каждой tenant-scoped таблице.
Code review rule: любой data access path проверяется на tenant isolation.
Обязательные automated tests на cross-tenant denial.
RLS на критичных таблицах.
Явный separation of duties между:
platform admin;
tenant owner;
tenant manager;
tenant staff.
Аудит всех privileged operations.
Отдельный secure export pipeline для выгрузок.
Tenant-aware cache keys.
Tenant-aware background jobs.
Tenant-aware observability labels без раскрытия чувствительных данных.
Scaling Strategy

Текущая модель является базовой для v1 и v2 платформы.

При росте продукта допускается hybrid evolution:

default tier: shared database, shared schema;
premium tier: dedicated database или dedicated deployment;
enterprise tier: stronger isolation by contract.

Такой эволюционный путь согласуется с тем, что tenancy models оцениваются по бизнес-драйверам и могут отличаться для разных сегментов клиентов.

Non-Goals

Это решение не покрывает полностью:

billing isolation;
cloud account isolation;
per-tenant deployment topology;
per-tenant encryption key management;
search and AI vector isolation details.

Эти вопросы фиксируются отдельными ADR.

Implementation Rules

Нормативные правила для кода проекта:

Все tenant-scoped ORM models обязаны наследовать tenant-aware base mixin.
Все repository methods обязаны принимать tenant identifier.
Нельзя создавать generic get_by_id(id) для tenant-scoped сущностей без tenant scope.
В API tenant должен извлекаться централизованно через request context.
Super-admin use cases должны быть вынесены в отдельный bounded path.
Все integration events должны содержать tenant_id, если они описывают tenant-scoped domain event.
Все materialized views, reports и analytics tables должны сохранять tenant boundary.
Все import/export сценарии должны проходить validation на соответствие tenant ownership.
Example of required SQL direction

Ниже пример направления, которое должна использовать команда на уровне БД:

ALTER TABLE bookings ENABLE ROW LEVEL SECURITY;

CREATE POLICY bookings_tenant_isolation_policy
ON bookings
USING (tenant_id = current_setting('app.current_tenant_id')::uuid)
WITH CHECK (tenant_id = current_setting('app.current_tenant_id')::uuid);

Пример отражает документированный PostgreSQL механизм: таблица переводится в режим RLS, после чего policy определяет, какие строки доступны для чтения и изменения.

Testing Requirements

Обязательные тесты tenancy model:

user from tenant A cannot read tenant B data;
user from tenant A cannot mutate tenant B data;
staff-scoped endpoints do not leak cross-tenant aggregates;
exports are restricted by tenant;
background jobs never execute with missing tenant context;
admin bypass flows are audited and restricted;
RLS policies fail closed when tenant context is absent.
Decision Summary

Для Reva Studio принята tenant model:

shared application;
shared database;
shared schema;
strict logical isolation by tenant_id;
mandatory authorization boundary;
PostgreSQL RLS for critical tables;
future-compatible upgrade path to hybrid or dedicated tenancy for premium clients.

Эта модель выбрана как лучший баланс между стоимостью, скоростью развития продукта, эксплуатационной простотой и контролируемой безопасностью для SaaS-платформы текущего масштаба. Trade-offs и механизмы tenant isolation подтверждаются актуальной документацией Microsoft, AWS, PostgreSQL и OWASP.

References
Microsoft Learn. Architect multitenant solutions on Azure.
Microsoft Learn. Tenancy models for a multitenant solution.
Microsoft Learn. Service-specific guidance for a multitenant solution.
AWS. SaaS Tenant Isolation Strategies.
AWS. The isolation mindset.
AWS. Identity and isolation.
PostgreSQL Documentation. Row Security Policies.
PostgreSQL Documentation. CREATE POLICY.
PostgreSQL Documentation. Rules and Privileges, security_barrier.
PostgreSQL Documentation. Predefined Roles and RLS behavior.
OWASP Cheat Sheet Series. Multi Tenant Security Cheat Sheet.
OWASP Cheat Sheet Series. Authorization Cheat Sheet.