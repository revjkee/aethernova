# ADR 0004: Authentication and RBAC

- Status: Accepted
- Date: 2026-03-22
- Deciders: Reva Studio Architecture
- Tags: security, auth, authorization, rbac, tenancy, fastapi, postgres

## Context

Reva Studio развивается как beauty SaaS-платформа с multi-tenant архитектурой, ролями сотрудников, административными функциями, клиентскими кабинетами, онлайн-записью, бонусной системой и финансовыми операциями.

Для такой системы недостаточно только базового логина. Нужна формальная модель, которая:

1. разделяет аутентификацию и авторизацию;
2. ограничивает доступ по tenant boundary;
3. задаёт предсказуемую ролевую модель;
4. поддерживает API и Telegram/WebApp сценарии;
5. позволяет безопасно отзывать доступ, ротацировать сессии и вести аудит;
6. минимизирует риск горизонтального повышения привилегий, утечек данных и ошибок доступа.

OWASP рекомендует проектировать авторизацию как явную, deny-by-default, проверяемую на каждом запросе и отделённую от аутентификации.  
Источник: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html

OWASP отдельно рекомендует безопасное хранение паролей, корректное управление сессиями и защиту токенов.  
Источники:  
https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html  
https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html  
https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

NIST SP 800-63B определяет актуальные требования к аутентификации и жизненному циклу аутентификаторов.  
Источник: https://pages.nist.gov/800-63-4/sp800-63b.html

FastAPI официально поддерживает security dependencies и OAuth2 scopes, что подходит для декларативной проверки прав на уровне endpoint.  
Источники:  
https://fastapi.tiangolo.com/tutorial/security/  
https://fastapi.tiangolo.com/advanced/security/oauth2-scopes/

PostgreSQL поддерживает Row-Level Security, что позволяет усиливать изоляцию tenant-данных на уровне БД.  
Источники:  
https://www.postgresql.org/docs/current/ddl-rowsecurity.html  
https://www.postgresql.org/docs/current/sql-createpolicy.html

## Decision

Мы принимаем следующую модель безопасности.

### 1. Authentication model

Используется централизованная аутентификация по логину и паролю.

Проектное правило Reva Studio:
- авторизация строится на логине и пароле;
- e-mail не является обязательной основой входа;
- пароль в открытом виде не хранится;
- доступ к системе предоставляется только после успешной проверки учётных данных и статуса аккаунта.

Пароли хранятся только в виде стойкого hash. Предпочтительный алгоритм: Argon2id. Если эксплуатационная среда требует иного стандарта, допускается контролируемый fallback согласно security policy. OWASP рекомендует Argon2id как основной вариант для password storage.  
Источник: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

### 2. Session and token model

Для API принимается схема:
- short-lived access token;
- refresh token с ротацией;
- server-side хранение token metadata для отзыва сессий;
- принудительное завершение сессий при reset credentials, disable user, role downgrade, tenant suspension.

Такой подход соответствует рекомендациям по управлению сессиями и снижает риск долгоживущих bearer credentials.  
Источник: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

### 3. Authorization model

Базовая модель авторизации: RBAC с возможностью точечных permission-based проверок.

Итоговая формула:
- роль задаёт базовый набор разрешений;
- permission определяет конкретное действие;
- tenant boundary всегда проверяется отдельно;
- ownership rule применяется там, где пользователь может работать только со своими сущностями;
- критичные операции требуют explicit permission, а не только факт наличия роли.

Это соответствует OWASP guidance по deny-by-default, least privilege и per-request authorization checks.  
Источник: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html

### 4. Multi-tenant isolation model

Изоляция tenant-данных обеспечивается в двух слоях:

1. application layer  
   Каждый запрос проходит через tenant resolution и tenant guard.

2. database layer  
   Для таблиц с tenant-bound данными используется `tenant_id` и RLS policy в PostgreSQL там, где это оправдано с точки зрения риска и стоимости сопровождения.

RLS в PostgreSQL применяется на уровне таблиц через `CREATE POLICY` и `ENABLE ROW LEVEL SECURITY`.  
Источники:  
https://www.postgresql.org/docs/current/ddl-rowsecurity.html  
https://www.postgresql.org/docs/current/sql-createpolicy.html

### 5. API authorization style

В FastAPI авторизация реализуется через dependency-based guards и security scopes.

Scope используется как транспортный и декларативный уровень для endpoint policy, а фактическая проверка прав выполняется через внутренний permission engine.  
Источник: https://fastapi.tiangolo.com/advanced/security/oauth2-scopes/

## Why this decision

Это решение выбрано по следующим причинам:

1. Оно отделяет identity verification от доступа к ресурсам.
2. Оно подходит для FastAPI backend и последующего расширения API.
3. Оно масштабируется на сотрудников, клиентов, администраторов и будущие partner-tenant сценарии.
4. Оно позволяет поддерживать least privilege и auditability.
5. Оно снижает риск cross-tenant data leak.
6. Оно совместимо с PostgreSQL и промышленной operational моделью.

## Security principles

В системе действуют следующие базовые принципы:

- deny by default;
- least privilege;
- explicit authorization on every request;
- separation of authentication, authorization and tenancy checks;
- defense in depth;
- secure password storage;
- auditable privileged actions;
- revocable sessions;
- sensitive operations require stronger controls.

Эти принципы соответствуют рекомендациям OWASP по authentication и authorization.  
Источники:  
https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html  
https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html

## Role model

### Global platform roles

Глобальные роли используются только для платформенных и эксплуатационных функций.

- `platform_super_admin`
- `platform_support`
- `platform_auditor`
- `platform_readonly_observer`

Эти роли не должны использоваться для повседневной бизнес-работы салона.

### Tenant roles

Основная рабочая модель внутри tenant:

- `tenant_owner`
- `tenant_admin`
- `salon_manager`
- `staff_master`
- `staff_assistant`
- `cashier`
- `marketing_manager`
- `support_agent`
- `client`

### Service principals

Для внутренних машинных интеграций:

- `service_internal`
- `service_scheduler`
- `service_webhook`
- `service_reporting`

Service principals не используют UI-access и получают только минимально необходимые permissions.

## Permission model

Права задаются не строкой роли, а явными permissions. Роль является только контейнером.

Формат permission:
`resource:action`

Примеры:
- `booking:create`
- `booking:read`
- `booking:update`
- `booking:cancel`
- `booking:assign`
- `client:read`
- `client:update`
- `staff:read`
- `staff:update`
- `schedule:read`
- `schedule:update`
- `service_catalog:read`
- `service_catalog:update`
- `loyalty:read`
- `loyalty:adjust`
- `payment:read`
- `payment:create`
- `payment:refund`
- `analytics:read`
- `tenant:update`
- `rbac:read`
- `rbac:update`
- `audit_log:read`

## Baseline role-to-permission mapping

Ниже задаётся базовая матрица. Конкретная конфигурация tenant может только ужесточать её, а не расширять произвольно без platform policy.

### `tenant_owner`
- полный доступ к tenant business configuration;
- доступ к staff management;
- доступ к RBAC management;
- доступ к payments, refunds, loyalty adjustments, analytics;
- просмотр audit logs своего tenant.

### `tenant_admin`
- почти полный операционный доступ;
- без platform-level действий;
- чувствительные операции могут требовать отдельного permission grant.

### `salon_manager`
- управление записями, мастерами, расписанием, клиентами;
- доступ к operational analytics;
- без управления tenant ownership;
- без изменения high-risk security settings.

### `staff_master`
- просмотр и управление собственным расписанием;
- работа со своими записями;
- чтение карточки клиента в объёме, необходимом для оказания услуги;
- без доступа к tenant-wide security settings;
- без массового экспорта клиентов.

### `staff_assistant`
- ограниченный доступ к расписанию и operational задачам;
- нет прав на refunds, rbac, tenant settings.

### `cashier`
- доступ к payment flows;
- нет доступа к security settings и staff management.

### `marketing_manager`
- доступ к promotions, loyalty campaigns, analytics;
- без доступа к критичным security и payment admin операциям.

### `support_agent`
- ограниченный operational read/helpdesk access;
- без доступа к raw secrets, credential data, password reset internals.

### `client`
- доступ только к собственному профилю, своим бонусам, своим записям, своим уведомлениям и своим платежам в разрешённом объёме.

## Mandatory policy rules

Независимо от роли действуют обязательные правила.

### Rule 1. Tenant boundary first
Если ресурс принадлежит другому tenant, доступ запрещается.

### Rule 2. Disabled or blocked user cannot act
Если аккаунт деактивирован, заблокирован или tenant suspended, доступ запрещается.

### Rule 3. Sensitive action needs explicit permission
Возвраты, изменение ролей, экспорт данных, просмотр audit log, изменение tenant settings и ручная корректировка loyalty не допускаются только по факту общей административной роли без соответствующего permission.

### Rule 4. Ownership matters
Для client-facing и staff-facing сценариев пользователь может работать только со своими сущностями, если не выдан расширенный operational permission.

### Rule 5. Read and write are separated
Право чтения не означает право изменения.

OWASP рекомендует моделировать доступ максимально явно и не допускать implicit privilege inheritance без проверки.  
Источник: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html

## Authentication flow

### Login flow

1. Пользователь отправляет login и password.
2. Система находит account по нормализованному логину.
3. Проверяется статус account, tenant и credential record.
4. Выполняется password verification по hash.
5. При успехе создаются:
   - access token;
   - refresh token;
   - session record;
   - audit event.
6. В access token включаются только необходимые claims.
7. На каждый запрос сервер повторно валидирует токен, статус субъекта и tenant context.

### Password storage requirements

- plaintext password не хранится;
- reversible encryption для паролей не используется;
- используется Argon2id;
- hash upgrade выполняется при успешной аутентификации, если policy изменилась;
- optional pepper хранится вне БД в secrets manager;
- требуется rate limiting и monitoring для login endpoints.

OWASP прямо указывает, что passwords should be hashed, not encrypted, и рекомендует modern password hashing algorithms.  
Источники:  
https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html  
https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html

### Password policy

Конкретные длины и UX-параметры задаются security policy, но архитектурно фиксируем:

- запрет на слабые и компрометированные пароли;
- server-side throttling / rate limiting;
- audit логирование попыток входа;
- принудительное завершение активных сессий после критичных credential events.

NIST SP 800-63B задаёт современный подход к аутентификации и lifecycle management.  
Источник: https://pages.nist.gov/800-63-4/sp800-63b.html

## Token design

### Access token claims

Минимальный состав claims:

- `sub` — идентификатор пользователя;
- `sid` — идентификатор сессии;
- `tid` — tenant id;
- `typ` — token type;
- `scp` — scopes;
- `iat`
- `exp`
- `jti`

В токен не включаются:
- password hashes;
- secrets;
- избыточные PII;
- полный список всех domain attributes пользователя.

### Refresh token rules

- refresh token rotation обязательна;
- reuse detection обязательна;
- компрометация refresh token приводит к revoke текущей session family;
- refresh token хранится в защищённом виде согласно server policy.

### Revocation model

Должны поддерживаться:
- revoke session;
- revoke all sessions for user;
- revoke all sessions for tenant;
- forced logout on role downgrade;
- forced logout on password change;
- forced logout on account disable.

## Authorization enforcement architecture

### Layer 1. Edge/API layer
FastAPI dependency проверяет:
- bearer token;
- token type;
- signature and expiry;
- required scopes.

### Layer 2. Identity and session layer
Проверяются:
- account status;
- tenant status;
- session status;
- revocation;
- risk flags.

### Layer 3. Domain authorization layer
Проверяются:
- role grants;
- permission grants;
- ownership rules;
- resource state restrictions;
- business invariants.

### Layer 4. Database isolation layer
Для tenant-bound таблиц применяется:
- обязательный `tenant_id`;
- repository filtering;
- при необходимости PostgreSQL RLS.

Такое многоуровневое применение соответствует принципу defense in depth.  
Источники:  
https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html  
https://www.postgresql.org/docs/current/ddl-rowsecurity.html

## Data model

Ниже фиксируется минимальный набор сущностей.

### `users`
- `id`
- `tenant_id`
- `login`
- `password_hash`
- `is_active`
- `is_blocked`
- `last_login_at`
- `created_at`
- `updated_at`

### `roles`
- `id`
- `tenant_id` nullable for global roles
- `code`
- `name`
- `is_system`
- `created_at`

### `permissions`
- `id`
- `code`
- `description`

### `role_permissions`
- `role_id`
- `permission_id`

### `user_roles`
- `user_id`
- `role_id`
- `tenant_id`

### `sessions`
- `id`
- `user_id`
- `tenant_id`
- `refresh_token_hash`
- `issued_at`
- `expires_at`
- `revoked_at`
- `revoked_reason`
- `ip`
- `user_agent`

### `audit_logs`
- `id`
- `tenant_id`
- `actor_user_id`
- `action`
- `resource_type`
- `resource_id`
- `result`
- `metadata`
- `created_at`

## Database controls

### Mandatory schema controls

- каждая tenant-bound таблица содержит `tenant_id`;
- на уровне application repository запрещены запросы без tenant filter;
- на критичных таблицах допускается PostgreSQL RLS;
- foreign keys связываются так, чтобы tenant mismatch был невозможен или детектировался;
- уникальные индексы проектируются с учётом tenant scope.

### RLS strategy

RLS включается для таблиц высокого риска:
- clients
- bookings
- loyalty_ledgers
- payments
- staff_profiles
- audit_logs

RLS не заменяет application authorization. Оно является дополнительным барьером.

Это соответствует природе PostgreSQL RLS, которое ограничивает доступ к строкам, но не отменяет необходимость корректной бизнес-авторизации на уровне приложения.  
Источники:  
https://www.postgresql.org/docs/current/ddl-rowsecurity.html  
https://www.postgresql.org/docs/current/predefined-roles.html

## Auditing

Обязательному аудиту подлежат:
- login success/failure;
- logout;
- password change;
- session revoke;
- role assignment/removal;
- permission changes;
- tenant settings changes;
- refunds;
- loyalty manual adjustments;
- exports of client data;
- suspicious access denials;
- privileged reads of audit logs.

Audit trail должен быть append-oriented и защищён от произвольного редактирования обычными operational ролями.

## Error handling and information disclosure

Система не должна раскрывать через ошибки:
- существует ли логин;
- какая именно часть credential pair неверна;
- внутреннюю security topology;
- полные детали privilege model.

OWASP рекомендует предотвращать избыточное раскрытие информации в authentication flows.  
Источник: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

## Operational controls

Обязательные operational controls:

- TLS для transport security;
- rate limiting для login, refresh, password reset-like endpoints;
- structured security logging;
- alerting на credential stuffing и brute force patterns;
- secret management вне исходного кода;
- separate signing keys per environment;
- key rotation process;
- регулярный access review для административных ролей.

OWASP рекомендует безопасное управление секретами, токенами и сессиями.  
Источники:  
https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html  
https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html

## Non-goals

Это решение не покрывает полностью:
- внешнюю федерацию через OIDC/SAML;
- social login;
- passwordless authentication;
- device trust framework;
- fine-grained ABAC engine;
- step-up authentication для отдельных операций.

Они могут быть добавлены отдельными ADR.

## Consequences

### Positive

- единая и проверяемая security model;
- масштабируемость для multi-tenant SaaS;
- предсказуемый permission model;
- снижение риска horizontal privilege escalation;
- улучшенный аудит и управляемость доступа;
- совместимость с FastAPI и PostgreSQL.

### Negative

- выше сложность реализации;
- требуется сопровождение role/permission matrices;
- RLS увеличивает сложность схемы и тестирования;
- revoke and rotation logic усложняет session lifecycle.

## Implementation notes

### FastAPI
Использовать:
- security dependencies;
- scoped endpoint guards;
- central authorization service;
- typed permission constants;
- request-scoped auth context.

Источник: https://fastapi.tiangolo.com/tutorial/security/

### PostgreSQL
Использовать:
- `tenant_id` как обязательный атрибут tenant-bound сущностей;
- индексы по `(tenant_id, ...)`;
- RLS для high-risk tables;
- отдельные миграции для security policies.

Источники:  
https://www.postgresql.org/docs/current/ddl-priv.html  
https://www.postgresql.org/docs/current/ddl-rowsecurity.html

## Testing requirements

Обязательные тесты:

1. unit tests
- permission evaluator
- role resolution
- ownership checks
- scope-to-permission mapping

2. integration tests
- cross-tenant access denied
- revoked session denied
- role downgrade invalidates sensitive action
- disabled user denied
- RLS policy behavior where enabled

3. security tests
- brute force throttling
- refresh token reuse detection
- broken object level authorization checks
- broken function level authorization checks

OWASP подчёркивает необходимость системной проверки authorization logic.  
Источник: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html

## Final decision summary

Для Reva Studio принимается промышленная модель:

- authentication по login/password;
- password hashing через Argon2id;
- short-lived access token плюс rotating refresh token;
- RBAC как основная модель;
- permissions как фактическая единица доступа;
- tenant boundary как обязательная независимая проверка;
- ownership rules для user-scoped ресурсов;
- database-level tenant isolation через `tenant_id`, а для high-risk данных дополнительно через PostgreSQL RLS;
- обязательный аудит привилегированных действий и жизненного цикла сессий.

## References

1. OWASP Authentication Cheat Sheet  
   https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

2. OWASP Authorization Cheat Sheet  
   https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html

3. OWASP Password Storage Cheat Sheet  
   https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

4. OWASP Session Management Cheat Sheet  
   https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

5. OWASP Cryptographic Storage Cheat Sheet  
   https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html

6. NIST SP 800-63B  
   https://pages.nist.gov/800-63-4/sp800-63b.html

7. FastAPI Security  
   https://fastapi.tiangolo.com/tutorial/security/

8. FastAPI OAuth2 Scopes  
   https://fastapi.tiangolo.com/advanced/security/oauth2-scopes/

9. PostgreSQL Row Security Policies  
   https://www.postgresql.org/docs/current/ddl-rowsecurity.html

10. PostgreSQL CREATE POLICY  
    https://www.postgresql.org/docs/current/sql-createpolicy.html

11. PostgreSQL Privileges  
    https://www.postgresql.org/docs/current/ddl-priv.html

12. PostgreSQL Predefined Roles  
    https://www.postgresql.org/docs/current/predefined-roles.html