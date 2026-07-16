# Audit Policy

## Status

Approved

## Document ID

SEC-AUDIT-POLICY-001

## Version

1.0.0

## Purpose

Настоящая политика определяет обязательные требования Reva Studio к аудиту, журналированию, защите, хранению, анализу и использованию аудиторских записей для приложений, сервисов, фоновых задач, административных интерфейсов, интеграций и инфраструктурных компонентов. Политика опирается на практики NIST по управлению журналами безопасности, семейство контролей Audit and Accountability из NIST SP 800-53, рекомендации OWASP по security logging и использование стандартизированного формата времени для системного обмена. :contentReference[oaicite:1]{index=1}

## Scope

Политика распространяется на:
- backend API
- admin panel
- Telegram bot
- background workers
- scheduler jobs
- database migration jobs
- integration adapters
- authentication and authorization flows
- CI and CD runtime audit events where applicable
- observability and security pipelines
- infrastructure components, если они входят в доверенный контур платформы

Политика не заменяет:
- incident response policy
- data retention policy
- privacy policy
- secrets management policy
- access control policy

Эти документы должны применяться совместно. NIST прямо рассматривает лог-менеджмент как часть общей программы безопасности, а NIST SP 800-53 рассматривает аудит и подотчётность как отдельное семейство контролей, связанное с более широким управлением риском. :contentReference[oaicite:2]{index=2}

## Objectives

Цели политики:
- обеспечить прослеживаемость действий пользователей, операторов, сервисов и автоматизаций
- поддерживать расследование инцидентов и аномалий
- обеспечивать контроль целостности и защищённости аудиторских данных
- поддерживать обнаружение злоупотреблений, ошибок и подозрительных действий
- обеспечивать воспроизводимость критических изменений
- исключать утечки секретов и чувствительных данных через логи
- стандартизировать формат, содержание и маршрутизацию аудиторских событий

Эти цели соответствуют назначению sound log management у NIST и практикам OWASP по security logging. :contentReference[oaicite:3]{index=3}

## Principles

### 1. Mandatory Auditability

Каждое критичное действие безопасности, доступа, изменения данных, изменения конфигурации или административного воздействия должно оставлять аудиторский след. NIST SP 800-53 выделяет audit events, content of audit records и audit generation как базовые требования семейства AU. :contentReference[oaicite:4]{index=4}

### 2. Least Exposure

Аудит не должен становиться каналом утечки секретов, паролей, токенов, сессионных идентификаторов, платёжных секретов, приватных ключей или иной чувствительной информации. OWASP отдельно рекомендует не журналировать секреты и указывает, что чувствительные данные вроде session ID не должны попадать в логи; для корреляции рекомендуется salted hash вместо самого идентификатора. :contentReference[oaicite:5]{index=5}

### 3. Integrity and Protection

Аудиторские записи должны быть защищены от несанкционированного доступа, удаления, подмены и неконтролируемого переписывания. Защита audit information и управление retention прямо входят в семейство AU NIST SP 800-53. :contentReference[oaicite:6]{index=6}

### 4. Time Consistency

Каждая запись должна содержать корректную временную метку. Для межсистемного обмена и хранения по умолчанию используется RFC 3339 timestamp в UTC. RFC 3339 определяет профиль ISO 8601 для интернет-протоколов; NIST SP 800-53 также выделяет time stamps как отдельный контроль AU-8. :contentReference[oaicite:7]{index=7}

### 5. Structured Logging by Default

Аудиторские события должны формироваться в структурированном формате, пригодном для поиска, корреляции, фильтрации и машинного анализа. OWASP рекомендует стандартизировать механизм логирования и словарь событий, а отдельный Logging Vocabulary Cheat Sheet предлагает единообразный словарь терминов. :contentReference[oaicite:8]{index=8}

### 6. Centralized Collection and Review

Аудиторские записи должны централизованно собираться, храниться и анализироваться в пределах доверенного контура. NIST рассматривает enterprise log management как практику разработки, внедрения и поддержания эффективного централизованного управления журналами; audit review, analysis and reporting также входит в семейство AU. :contentReference[oaicite:9]{index=9}

## Policy Statements

### 1. What Must Be Logged

Следующие категории событий подлежат обязательному аудиту:

#### 1.1 Authentication and Session Security
- успешная аутентификация
- неуспешная аутентификация
- logout
- password change
- password reset request
- password reset completion
- MFA enrollment
- MFA reset
- MFA challenge success or failure
- account lock
- suspicious login flow
- session revocation
- privileged session start or end

OWASP рекомендует журналировать успешную и неуспешную аутентификацию, а также другие security-relevant events. :contentReference[oaicite:10]{index=10}

#### 1.2 Authorization and Access Control
- access denied
- role change
- permission grant
- permission revoke
- privileged action execution
- policy bypass attempt
- failed access to protected resource
- access to audit or security administration functions

Такие события относятся к security logging и подотчётности действий пользователей. NIST SP 800-53 требует auditability событий, достаточных для расследования и подотчётности. :contentReference[oaicite:11]{index=11}

#### 1.3 Administrative and Configuration Changes
- изменение конфигурации приложения
- изменение security settings
- изменение feature flags, влияющих на безопасность
- изменение retention settings
- изменение logging level
- включение или отключение audit sinks
- изменение secrets references или trust configuration
- запуск и завершение миграций с чувствительным эффектом

Изменения конфигурации и управляющих механизмов относятся к событиям, важным для анализа и расследования, а отсутствие их аудита снижает возможность контроля. :contentReference[oaicite:12]{index=12}

#### 1.4 Data and Domain Critical Actions
- создание, изменение, удаление и восстановление критичных бизнес-сущностей
- изменение статуса бронирования
- ручное изменение бонусного баланса
- изменение цен или витринных условий
- выпуск, отзыв или переназначение промокодов
- экспорт данных
- импорт данных
- массовые операции
- ручные административные override-операции

OWASP рекомендует аудит application actions, особенно важных операций и data manipulation, включая CRUD на чувствительных объектах. :contentReference[oaicite:13]{index=13}

#### 1.5 Security and Operational Events
- ошибка валидации security policy
- срабатывание rate limit
- подозрительный input pattern
- попытка доступа к несуществующим или запрещённым маршрутам
- изменение trust boundary behavior
- отказ интеграции, влияющий на безопасность
- исключения, влияющие на confidentiality, integrity или availability
- запуск и остановка сервиса
- деградация audit pipeline
- потеря доставки audit events
- отказ хранилища логов

OWASP Logging Cheat Sheet ориентирован именно на security logging, а NIST подчёркивает необходимость разрабатывать эффективные log management practices для enterprise-level security operations. :contentReference[oaicite:14]{index=14}

### 2. Minimum Required Fields

Каждая аудиторская запись должна содержать минимум:

- `event_id`
- `event_name`
- `event_category`
- `occurred_at`
- `recorded_at`
- `outcome`
- `severity`
- `actor_type`
- `actor_id` или технический сервисный идентификатор
- `target_type`
- `target_id`, если применимо
- `source_ip`, если применимо и допустимо
- `user_agent`, если применимо
- `request_id`
- `trace_id`
- `span_id`, если используется tracing
- `service_name`
- `service_version`
- `environment`
- `correlation_id`, если используется межсервисная корреляция
- `reason_code` или `failure_code`, если применимо
- `message`, безопасная для отображения и поиска
- `metadata`, ограниченный структурированный объект без секретов

OWASP Developer Guide отмечает, что каждая запись должна содержать timestamp и другие важные атрибуты события, а NIST SP 800-53 выделяет content of audit records и time stamps как отдельные контролируемые области. :contentReference[oaicite:15]{index=15}

### 3. Timestamp Standard

Поле `occurred_at` должно записываться в UTC в формате RFC 3339.
Пример:
`2026-03-23T14:05:17Z`

Если система не может гарантировать точную синхронизацию времени, это должно фиксироваться как operational risk и отдельное событие наблюдаемости. RFC 3339 определяет профиль ISO 8601 для интернет-времени, а NIST AU-8 требует time stamps для audit record generation. :contentReference[oaicite:16]{index=16}

### 4. Event Outcome and Severity

Каждое событие должно иметь:
- `outcome`: success, failure, denied, error, partial
- `severity`: debug, info, notice, warning, error, critical

OWASP рекомендует единообразную классификацию security events и использование стандартизированного словаря для мониторинга и alerting. :contentReference[oaicite:17]{index=17}

### 5. Sensitive Data Prohibitions

Запрещено писать в аудит:
- plaintext passwords
- password hashes, кроме специально разрешённых тестовых стендов без прод-данных
- access tokens
- refresh tokens
- API secrets
- OTP values
- full session IDs
- private keys
- raw payment secrets
- необработанные персональные данные сверх подтверждённой необходимости
- полные данные документов, если для операции достаточно маскированного представления
- диагностические дампы, содержащие секреты
- произвольный request body целиком по умолчанию

OWASP прямо предупреждает не включать чувствительные данные в логи и отдельно рекомендует не журналировать session ID в явном виде. :contentReference[oaicite:18]{index=18}

Разрешено журналировать:
- masked identifiers
- salted hash session correlation values
- reference IDs
- surrogate keys
- минимальный набор данных, достаточный для расследования

### 6. Data Minimization and Privacy

Аудит должен собирать только тот объём данных, который необходим для расследования, корреляции и соблюдения требований безопасности. Политика минимизации обязательна для того, чтобы логи не становились несанкционированным хранилищем чувствительной информации. Эта позиция согласуется с OWASP guidance по исключению sensitive data из логов и с NIST подходом к управляемому и осмысленному log management. :contentReference[oaicite:19]{index=19}

### 7. Audit Record Immutability and Protection

Аудиторские записи после записи не должны редактироваться обычными приложениями.
Допустимы только:
- append-only pattern
- write-once transport semantics, где это поддерживается платформой
- административные операции retention management в рамках регламентированной процедуры
- криптографически или системно защищённые механизмы доставки и хранения, если они внедрены в платформе

Доступ на удаление, массовую правку или переписывание аудита должен быть ограничен отдельной административной ролью и отдельным процессом change control. Требование защиты audit information и retention отражено в контролях AU-9 и AU-11 семейства NIST SP 800-53. :contentReference[oaicite:20]{index=20}

### 8. Access Control for Audit Data

Доступ к аудиторским данным предоставляется только:
- security operators
- platform administrators с подтверждённой производственной ролью
- incident responders
- auditors по согласованной процедуре
- limited read consumers для строго определённых агрегированных представлений

Просмотр и экспорт audit data должен сам журналироваться. Ограничение доступа к логам и trusted logging environment рекомендуются OWASP, а защита audit information закреплена в NIST AU family. :contentReference[oaicite:21]{index=21}

### 9. Central Collection

Все production аудиторские записи должны отправляться в централизованный контур сбора, хранения и анализа. Локальные файлы сервиса не считаются достаточным хранилищем аудита, кроме временного буфера при деградации pipeline. NIST SP 800-92 рассматривает enterprise log management как практику организации и сопровождения эффективного сбора и управления журналами; OWASP также указывает на необходимость эффективного logging mechanism и monitoring. :contentReference[oaicite:22]{index=22}

### 10. Review and Monitoring

Аудиторские записи должны:
- автоматически анализироваться на критичные шаблоны
- поддерживать корреляцию по actor, request, trace и target
- быть доступны для расследований
- использоваться для оповещений по критичным security events
- подвергаться регулярному review ответственными ролями

NIST AU включает audit review, analysis and reporting, а OWASP Top 10 подчёркивает важность consistent logging, monitoring suspicious behavior и effective alerting. :contentReference[oaicite:23]{index=23}

### 11. Logging Failures

Отказ аудита сам по себе является значимым событием безопасности и эксплуатации. Система должна журналировать:
- write failure
- queue saturation
- sink unavailable
- schema validation failure for audit event
- fallback activation
- dropped event count
- clock skew detection, если реализовано

Если событие не может быть доставлено в основной audit sink, система должна использовать безопасный fallback механизм, а факт fallback должен быть зафиксирован. Требование контролировать generation и storage-related risks следует из NIST log management guidance и AU control family. :contentReference[oaicite:24]{index=24}

### 12. Retention

Срок хранения аудита определяется классификацией события, требованиями безопасности, расследований, compliance и операционной необходимостью. Эта политика не задаёт единый универсальный срок хранения для всех классов событий без отдельной матрицы хранения, потому что такое значение должно утверждаться бизнесом, безопасностью и юридической функцией. Не могу подтвердить единый корректный срок хранения без вашей утверждённой retention matrix.

При этом сама обязанность управлять retention и защищать audit records подтверждается NIST AU-11 и общим guidance по log management. :contentReference[oaicite:25]{index=25}

### 13. Synchronization with Incident Response

Критичные security events из аудита должны использоваться в процессах triage, incident detection и расследования. Это соответствует назначению security logging у OWASP и практикам NIST для operational analysis of logs. :contentReference[oaicite:26]{index=26}

## Required Event Categories

Стандартизированные категории событий:

- `auth`
- `session`
- `access_control`
- `admin_action`
- `configuration_change`
- `business_critical_change`
- `security_detection`
- `integration_security`
- `data_export`
- `data_import`
- `privacy_sensitive_operation`
- `audit_system`
- `availability_event`
- `compliance_event`

Стандартизированная категоризация и vocabulary упрощают monitoring и alerting, что прямо указано OWASP Logging Vocabulary Cheat Sheet. :contentReference[oaicite:27]{index=27}

## Required Event Schema

Пример обязательной структуры:

```json
{
  "event_id": "01HRM7JQ4PH1J7H6Q3M2J1WQ6A",
  "event_name": "auth.login.failed",
  "event_category": "auth",
  "occurred_at": "2026-03-23T14:05:17Z",
  "recorded_at": "2026-03-23T14:05:17Z",
  "outcome": "failure",
  "severity": "warning",
  "actor_type": "user",
  "actor_id": "usr_123456",
  "target_type": "account",
  "target_id": "usr_123456",
  "source_ip": "203.0.113.10",
  "user_agent": "Mozilla/5.0",
  "request_id": "req_01HRM7JPKJ3D9A2V6KX",
  "trace_id": "2f1c0b31b93d4f8a9f3ed7bb0d202111",
  "span_id": "9c6de9a2010f77aa",
  "service_name": "rvstd-api",
  "service_version": "1.8.0",
  "environment": "production",
  "reason_code": "INVALID_CREDENTIALS",
  "message": "User authentication failed",
  "metadata": {
    "mfa_required": true,
    "session_hash": "sha256:masked_or_salted_value"
  }
}