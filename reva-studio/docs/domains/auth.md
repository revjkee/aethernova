# Auth Domain

## Назначение

Домен `auth` отвечает за аутентификацию, авторизацию, управление сессиями, токенами, политиками доступа, безопасностью входа, восстановлением доступа и связанными audit-событиями в Reva Studio.

Этот домен не является только "логином и паролем". Он задаёт доверенную границу всей платформы:

- кто именно совершает действие
- имеет ли субъект право на это действие
- в каком tenant-контексте выполняется запрос
- как обеспечивается защита от повторов, компрометации, перебора и захвата сессий
- как фиксируются критические security-события

## Цели домена

`auth` должен обеспечивать:

- надёжную идентификацию пользователя
- безопасную выдачу access и refresh токенов
- изоляцию tenant-контекста
- ролевую и permission-based авторизацию
- управляемую lifecycle-модель сессий
- безопасное восстановление доступа
- аудит критичных событий безопасности
- идемпотентное и предсказуемое поведение внешних auth-flow
- расширяемость под будущие способы входа и интеграции

## Не-цели домена

Домен `auth` не должен:

- хранить бизнес-логику бронирований
- принимать решения по loyalty, promotions, CRM и analytics
- напрямую управлять контентом профиля клиента или сотрудника вне auth-сущностей
- смешивать authentication и business authorization в одном неразделённом слое
- делать frontend источником истины по правам доступа

## Границы домена

### Входит в auth

- учётные записи
- credential-модель
- password hashing
- login flow
- logout flow
- refresh flow
- access control
- roles
- permissions
- session tracking
- password reset
- email verification
- phone verification
- MFA-ready контуры
- device/session revocation
- security audit trail
- lockout / throttling
- token issuing / token revocation

### Не входит в auth

- профиль мастера
- карточка клиента
- расписания
- услуги
- bookings
- loyalty wallet
- payment processing
- marketing subscriptions как бизнес-домен
- общие notification-кампании

## Архитектурный принцип

Auth-домен должен быть отделён от прикладной логики платформы и рассматриваться как security-critical bounded context.

Основные принципы:

1. Источник истины по identity и access policy находится на backend.
2. Проверка прав выполняется server-side.
3. Любой внешний запрос рассматривается как недоверенный до успешной проверки identity, tenant scope и permission policy.
4. Security-состояние не должно определяться только клиентскими cookie, local storage или UI-флагами.
5. Любое критичное изменение auth-состояния должно быть audit-ируемым.

## Ключевые сценарии

### Аутентификация

Поддерживаемые базовые сценарии:

- вход по логину и паролю
- обновление access token по refresh token
- завершение текущей сессии
- завершение всех активных сессий
- принудительная ревокация сессий администратором или системой риска

### Восстановление доступа

- запрос reset token
- проверка действительности reset token
- установка нового пароля
- инвалидирование старых refresh token после смены пароля
- аудит события смены пароля

### Верификация

- подтверждение email
- подтверждение телефона
- будущая поддержка step-up verification

### Авторизация

- назначение роли
- вычисление effective permissions
- tenant-scoped access
- запрет выхода за границы tenant
- разделение client, staff, admin, owner, system actor

## Модель ответственности

### Authentication

Authentication отвечает на вопрос:

`Кто это?`

В рамках домена это означает:

- проверка credential
- выдача identity context
- создание сессии
- выпуск токенов
- проверка действительности токена или сессии

### Authorization

Authorization отвечает на вопрос:

`Что этому субъекту разрешено?`

В рамках домена это означает:

- проверка роли
- проверка permission
- проверка tenant scope
- проверка статуса учётной записи
- проверка дополнительных ограничений доступа

### Accounting / Audit

Accounting отвечает на вопрос:

`Что именно произошло, кто это сделал и когда?`

В рамках домена это означает:

- логирование security events
- корреляцию по actor_id, tenant_id, session_id, request_id
- хранение следов входа, выхода, ревокации, lockout, password reset и privilege changes

## Основные сущности домена

### User

Представляет identity субъекта.

Минимальные поля:

- `id`
- `tenant_id`
- `login`
- `email`
- `phone`
- `status`
- `is_active`
- `is_superuser`
- `created_at`
- `updated_at`
- `last_login_at`

Замечания:

- `login` должен быть уникален в рамках выбранной модели уникальности
- `tenant_id` обязателен для tenant-scoped identities, если не используется специальный global actor
- `status` не должен заменяться булевым флагом, если требуется расширяемая lifecycle-модель

### Credential

Хранит credential-related данные отдельно от общего профиля.

Поля:

- `user_id`
- `password_hash`
- `password_changed_at`
- `password_version`
- `must_change_password`
- `failed_login_attempts`
- `locked_until`
- `last_failed_login_at`

### Session

Представляет серверное понятие доверенной сессии.

Поля:

- `id`
- `user_id`
- `tenant_id`
- `refresh_token_id`
- `device_fingerprint`
- `ip_address`
- `user_agent`
- `created_at`
- `last_seen_at`
- `expires_at`
- `revoked_at`
- `revocation_reason`

### Role

Роль — агрегированная группа прав.

Поля:

- `id`
- `tenant_id`
- `code`
- `name`
- `description`
- `is_system`
- `created_at`
- `updated_at`

### Permission

Гранулярное право.

Поля:

- `id`
- `code`
- `resource`
- `action`
- `description`

Примеры:

- `bookings.read`
- `bookings.create`
- `bookings.update`
- `staff.manage`
- `users.invite`
- `loyalty.adjust`
- `admin.access`

### UserRole

Связь пользователя с ролью.

Поля:

- `user_id`
- `role_id`
- `assigned_by`
- `assigned_at`

### AuditEvent

Security и compliance-след событий.

Поля:

- `id`
- `tenant_id`
- `actor_user_id`
- `actor_type`
- `event_type`
- `target_type`
- `target_id`
- `session_id`
- `request_id`
- `ip_address`
- `user_agent`
- `metadata`
- `created_at`

## Статусы учётной записи

Рекомендуемая lifecycle-модель пользователя:

- `pending_verification`
- `active`
- `suspended`
- `locked`
- `disabled`
- `deleted`

Описание:

- `pending_verification`: пользователь создан, но не завершил обязательную проверку
- `active`: пользователь может выполнять разрешённые действия
- `suspended`: доступ ограничен административным решением или policy
- `locked`: временная блокировка из-за security policy
- `disabled`: постоянное отключение учётной записи
- `deleted`: логически удалённая запись без hard delete в обычном flow

## Статусы сессии

Сессия логически может быть:

- `active`
- `expired`
- `revoked`

Практически статус может вычисляться из timestamp-полей:

- если `revoked_at` заполнен, сессия revoked
- если `expires_at` в прошлом, сессия expired
- иначе active

## Security policy

### Пароли

Требования:

- хранить только безопасный hash
- не хранить пароль в открытом виде
- не логировать пароль ни при каких условиях
- обеспечивать password rotation через `password_changed_at` и `password_version`
- при смене пароля инвалидировать старые refresh token и, по policy, активные сессии

### Брутфорс-защита

Необходимые меры:

- rate limiting на login endpoint
- tracking failed login attempts
- временная блокировка после порога неудачных попыток
- audit на lockout
- единообразные ошибки без раскрытия лишней информации

### Токены

Access token:

- короткоживущий
- используется для авторизации запросов
- не должен быть единственным persistent security state

Refresh token:

- длиннее по TTL
- должен быть привязан к session record
- должен поддерживать revocation
- должен быть rotation-ready

### Ревокация

Система должна поддерживать:

- logout текущей сессии
- logout всех сессий пользователя
- ревокацию при смене пароля
- ревокацию при повышении риска
- ревокацию при административной блокировке аккаунта

## Tenant model

Reva Studio проектируется как multi-tenant система, поэтому auth обязан быть tenant-aware.

Правила:

1. Каждый auth context должен содержать tenant identity.
2. Пользователь не должен получать доступ к ресурсам другого tenant.
3. Role assignment должен быть tenant-scoped, кроме явно системных ролей.
4. Permission evaluation должен учитывать tenant boundary.
5. Любой токен без tenant scope должен считаться неполным, если endpoint требует tenant context.

### Пример auth context

```text
subject_id=<uuid>
tenant_id=<uuid>
session_id=<uuid>
roles=[staff_manager]
permissions=[bookings.read, bookings.update, staff.read]
status=active