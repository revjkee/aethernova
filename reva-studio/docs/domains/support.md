# Support Domain

## Document Status

Accepted

## Version

1.0.0

## Purpose

Этот документ фиксирует промышленную модель домена `support` для Reva Studio.

Домен `support` отвечает за:

- приём и маршрутизацию обращений;
- ведение тикетов поддержки;
- обработку инцидентов и сервисных запросов;
- эскалации;
- SLA и контроль сроков;
- внутренние комментарии и коммуникацию;
- связь тикетов с tenant, пользователями, бронированиями, оплатами и интеграциями;
- аудит действий поддержки;
- формирование post-incident follow-up и corrective actions.

Решение принято так, чтобы support был совместим с multi-tenant архитектурой Reva Studio и не нарушал tenant isolation.

## External Foundations

Ниже перечислены внешние опоры, на которых основаны фактические части этого документа:

1. Microsoft Learn описывает incident и problem management как help desk ticketing процессы и подчёркивает использование Impact, Urgency, Assigned Analyst и Support Tier в инцидентной работе. :contentReference[oaicite:1]{index=1}
2. Google SRE рекомендует заранее документировать incident process, минимизировать user impact, сохранять evidence для root cause analysis и строить incident response вокруг coordination, communication и control. :contentReference[oaicite:2]{index=2}
3. Google SRE рекомендует blameless postmortem, конкретные action items, ownership и своевременную публикацию результатов инцидента. :contentReference[oaicite:3]{index=3}
4. OWASP указывает, что application logging должен быть согласованным, полезным для operational и security use cases, и что логи не должны превращаться в утечку чувствительных данных. :contentReference[oaicite:4]{index=4}
5. RFC 9457 определяет `problem details` как стандартный формат machine-readable ошибок для HTTP API. :contentReference[oaicite:5]{index=5}

## Domain Goal

Поддержка в Reva Studio должна решать четыре задачи одновременно:

1. Быстро восстанавливать работу пользователя и tenant.
2. Давать прозрачный операционный процесс для staff, admin и support team.
3. Не допускать смешивания данных разных tenants.
4. Превращать повторяющиеся сбои и обращения в улучшения продукта.

## Domain Scope

### In Scope

Внутри домена `support` находятся:

- support tickets;
- incident tickets;
- service requests;
- internal escalation;
- assignment and ownership;
- SLA policy application;
- priority calculation;
- ticket comments;
- attachments metadata;
- linked resources;
- support audit events;
- support reporting;
- postmortem and follow-up records.

### Out of Scope

Вне домена `support` остаются:

- аутентификация и сессии;
- биллинг как отдельный bounded context;
- непосредственное выполнение notification delivery;
- core booking orchestration;
- CRM и loyalty logic;
- observability platform как самостоятельный домен.

Эти домены могут быть связаны с `support`, но не принадлежат ему.

## Domain Principles

### 1. Tenant isolation is mandatory

Каждый тикет принадлежит ровно одному tenant, кроме строго ограниченного platform-level support case.

Tenant boundary обязательна для:

- чтения тикета;
- назначения исполнителя;
- просмотра комментариев;
- просмотра вложений;
- построения отчётов;
- экспорта.

### 2. One source of truth for support work

Любая единица работы поддержки фиксируется тикетом. Запрещено вести критичные запросы только в чате, без ticket record.

### 3. Fast recovery first, deep analysis second

Для инцидентов приоритетом является восстановление работы и снижение пользовательского ущерба. Этот принцип соответствует Google SRE: сначала остановить ущерб, восстановить сервис и сохранить evidence для последующего root cause analysis. :contentReference[oaicite:6]{index=6}

### 4. Blameless learning

Postmortem и follow-up не должны обвинять конкретных людей. Google SRE прямо указывает, что blameful narrative ухудшает качество культуры и мешает предотвращению повторов. :contentReference[oaicite:7]{index=7}

### 5. Auditability by design

Ключевые действия поддержки обязаны логироваться и быть пригодными для операционного и security анализа. Это согласуется с OWASP Logging Cheat Sheet. :contentReference[oaicite:8]{index=8}

## Domain Language

### Ticket

Универсальная запись поддержки, представляющая единицу работы.

### Incident

Тикет, описывающий нарушение доступности, корректности или качества сервиса, которое требует оперативного восстановления. Microsoft и Google используют incident management как отдельный тип процесса. :contentReference[oaicite:9]{index=9}

### Service Request

Тикет на изменение, помощь, настройку, разъяснение, импорт, экспорт, подключение или другую неаварийную операцию.

### Problem

Корневая проблема, которая может стоять за несколькими инцидентами или повторяющимися обращениями. Microsoft разделяет incidents и problems как связанные, но разные управленческие сущности. :contentReference[oaicite:10]{index=10}

### Support Case

Общий термин для любого обращения, которым занимается команда поддержки.

### Escalation

Передача тикета на другой уровень поддержки, другой домен или в engineering ownership.

### SLA

Целевые сроки реакции и решения для тикета или инцидента.

### Postmortem

Структурированный разбор инцидента после стабилизации, с фактами, причинами, timeline и action items. Google SRE рекомендует именно такой формат. :contentReference[oaicite:11]{index=11}

## Ticket Taxonomy

### Ticket Types

В Reva Studio фиксируются следующие типы:

- `incident`
- `service_request`
- `question`
- `bug_report`
- `billing_support`
- `integration_support`
- `data_correction`
- `access_request`
- `security_report`
- `complaint`
- `postmortem_followup`

### Why this split exists

Такое деление нужно, чтобы:

- не смешивать аварийную работу с обычной поддержкой;
- по-разному считать SLA;
- различать restore-work и change-work;
- по-разному маршрутизировать тикеты.

Это соответствует внешней практике раздельного incident/problem handling и help desk ticketing. :contentReference[oaicite:12]{index=12}

## Severity, Impact, Urgency, Priority

Microsoft в incident handling явно использует `Impact` и `Urgency`; поэтому в Reva Studio priority не задаётся вручную как свободный текст, а вычисляется по матрице. :contentReference[oaicite:13]{index=13}

### Severity

Severity используется прежде всего для `incident`.

Допустимые значения:

- `sev1`
- `sev2`
- `sev3`
- `sev4`

Смысл:

- `sev1` — полная недоступность критичной функции tenant или платформы, массовый пользовательский ущерб;
- `sev2` — серьёзная деградация ключевого сценария, обходной путь отсутствует или сильно ограничен;
- `sev3` — частичная деградация, есть обходной путь;
- `sev4` — низкий операционный ущерб, нет немедленного user-facing риска.

### Impact

Допустимые значения:

- `critical`
- `high`
- `medium`
- `low`

### Urgency

Допустимые значения:

- `immediate`
- `high`
- `normal`
- `low`

### Priority

Итоговый приоритет:

- `p1`
- `p2`
- `p3`
- `p4`

### Priority Matrix

Нормативное правило:

- `critical + immediate => p1`
- `critical + high => p1`
- `high + immediate => p1`
- `high + high => p2`
- `medium + high => p2`
- `medium + normal => p3`
- `low + normal => p4`
- `low + low => p4`

Дополнительное правило:

- любой `security_report`, подтверждённый как активный риск компрометации tenant data, автоматически не ниже `p1`.

## Ticket Lifecycle

### States

Единый lifecycle для большинства тикетов:

- `new`
- `triaged`
- `assigned`
- `in_progress`
- `waiting_customer`
- `waiting_internal`
- `pending_release`
- `resolved`
- `closed`
- `cancelled`

### Incident-specific states

Для `incident` дополнительно разрешены:

- `mitigating`
- `monitoring`
- `postmortem_required`

### Transition Rules

#### Generic rules

- `new -> triaged`
- `triaged -> assigned`
- `assigned -> in_progress`
- `in_progress -> waiting_customer`
- `in_progress -> waiting_internal`
- `in_progress -> pending_release`
- `in_progress -> resolved`
- `resolved -> closed`
- `new|triaged|assigned -> cancelled`

#### Incident rules

- `in_progress -> mitigating`
- `mitigating -> monitoring`
- `monitoring -> resolved`
- `resolved -> postmortem_required`
- `postmortem_required -> closed`

### Close conditions

Тикет может быть закрыт только если:

1. есть итоговое resolution summary;
2. заполнен resolution code;
3. нет открытых обязательных внутренних follow-up задач;
4. для required incident завершён postmortem stub или linked postmortem record.

## Roles and Responsibilities

Google SRE подчёркивает полезность заранее определённых ролей и ясных каналов коммуникации во время инцидента. :contentReference[oaicite:14]{index=14}

### Roles

#### Reporter

Тот, кто создал обращение.

#### Support Agent

Первая линия поддержки. Выполняет triage, коммуникацию и типовые решения.

#### Support Lead

Контролирует очередь, SLA breach risk и эскалации.

#### Incident Commander

Назначается на `sev1` и `sev2` инциденты. Координирует response.

#### Communications Lead

Ведёт stakeholder updates по крупным инцидентам.

#### Operations/Engineering Owner

Исполняет техническое устранение проблемы.

#### Tenant Admin

Представитель салона или организации, уполномоченный подтверждать изменения и получать расширенную информацию по своему tenant.

#### Security Reviewer

Подключается к security-related cases.

### Responsibility Model

#### Support Agent must

- принять тикет;
- провести первичный triage;
- привязать tenant;
- классифицировать тип;
- проверить приоритет;
- назначить owner или escalate.

#### Incident Commander must

- координировать response;
- следить за timeline;
- фиксировать решения;
- минимизировать user impact;
- обеспечить postmortem handoff.

#### Communications Lead must

- давать регулярные обновления;
- вести единый источник статуса;
- не допускать противоречивых сообщений.

## SLA Model

Этот раздел является проектным решением Reva Studio. Внешние источники подтверждают важность structured incident handling и timely response, но конкретные числа ниже являются внутренним design choice. :contentReference[oaicite:15]{index=15}

### Response SLA

- `p1` — first response до 15 минут
- `p2` — first response до 1 часа
- `p3` — first response до 8 рабочих часов
- `p4` — first response до 2 рабочих дней

### Resolution Targets

- `p1` — target mitigation до 1 часа, target stable recovery до 4 часов
- `p2` — target mitigation до 4 часов, target recovery до 1 рабочего дня
- `p3` — target resolution до 5 рабочих дней
- `p4` — target resolution до 10 рабочих дней

### SLA Pausing

SLA timer может быть paused только в состояниях:

- `waiting_customer`
- `waiting_internal` при документированной внешней зависимости

### SLA Breach Rules

При риске нарушения SLA система обязана:

1. создать escalation event;
2. уведомить Support Lead;
3. пометить тикет как `at_risk`;
4. записать audit event.

## Support Data Model

### Aggregate: SupportTicket

`SupportTicket` — основной aggregate root домена.

#### Fields

- `id`
- `ticket_number`
- `tenant_id`
- `type`
- `status`
- `severity`
- `impact`
- `urgency`
- `priority`
- `channel`
- `subject`
- `description`
- `reporter_user_id`
- `reporter_contact`
- `assigned_team`
- `assigned_agent_id`
- `incident_commander_id`
- `communications_lead_id`
- `linked_problem_id`
- `linked_booking_id`
- `linked_payment_id`
- `linked_client_id`
- `linked_staff_id`
- `root_cause_summary`
- `resolution_summary`
- `resolution_code`
- `postmortem_required`
- `first_response_due_at`
- `resolution_due_at`
- `first_responded_at`
- `resolved_at`
- `closed_at`
- `created_at`
- `updated_at`

### Child Entities

#### TicketComment

- `id`
- `ticket_id`
- `tenant_id`
- `author_id`
- `visibility`
- `body`
- `created_at`
- `edited_at`

`visibility`:

- `internal`
- `customer_visible`

#### TicketAttachmentRef

- `id`
- `ticket_id`
- `tenant_id`
- `storage_key`
- `original_filename`
- `content_type`
- `size_bytes`
- `checksum`
- `uploaded_by`
- `created_at`

#### TicketLink

- `id`
- `ticket_id`
- `target_type`
- `target_id`
- `relation`

`relation`:

- `duplicates`
- `caused_by`
- `relates_to`
- `blocks`
- `blocked_by`
- `spawned_postmortem`
- `spawned_problem`

#### SLAClock

- `id`
- `ticket_id`
- `metric_type`
- `started_at`
- `paused_at`
- `resumed_at`
- `breached_at`
- `stopped_at`

### Aggregate: ProblemRecord

Используется для повторяющихся или системных причин.

#### Fields

- `id`
- `tenant_id` nullable
- `scope`
- `title`
- `summary`
- `status`
- `owner_team`
- `root_cause`
- `known_error`
- `workaround`
- `created_at`
- `updated_at`

`scope`:

- `tenant`
- `platform`

## Support Channels

Поддерживаются каналы:

- `telegram`
- `web_admin`
- `internal_console`
- `email`
- `phone_manual`
- `system_generated`

### Rules

1. Любой канал должен нормализоваться в единый `SupportTicket`.
2. Телефонные обращения создаются вручную оператором.
3. Автоматически созданные тикеты обязаны иметь `channel = system_generated`.
4. Дубликаты должны детектироваться по tenant, типу, subject fingerprint и близости по времени.

## Triage Rules

### Required triage fields

Перед переводом из `new` в `triaged` обязательны:

- `tenant_id`
- `type`
- `subject`
- `priority`
- `reporter`
- `channel`

### Triage checklist

Support Agent обязан проверить:

1. есть ли затронутая запись, платёж, клиент, мастер или интеграция;
2. является ли проблема единичной или массовой;
3. есть ли обходной путь;
4. затронута ли безопасность или персональные данные;
5. требуется ли срочное уведомление tenant admin;
6. требуется ли escalation.

## Incident Management Model

Google SRE рекомендует готовить process заранее, строить response вокруг coordination, communication и control, а также использовать actionable alerting и playbooks. :contentReference[oaicite:16]{index=16}

### Incident declaration

`incident` должен быть объявлен, если хотя бы одно условие истинно:

- недоступен booking flow;
- массово ломается customer-facing функциональность;
- есть риск потери данных;
- есть риск некорректных списаний или начислений;
- есть подтверждённая security compromise;
- множество tenants затронуты одновременно;
- ошибка не ограничивается единичным пользователем и воспроизводится системно.

### Mandatory incident artifacts

Для `sev1` и `sev2` обязательны:

- incident owner;
- communications lead;
- timeline log;
- mitigation log;
- final summary;
- postmortem record.

### Incident update cadence

Внутреннее правило Reva Studio:

- `sev1` — статус не реже чем каждые 15 минут
- `sev2` — статус не реже чем каждые 30 минут
- `sev3` — по изменению статуса или не реже чем каждые 4 часа

## Postmortem Policy

Google SRE рекомендует blameless postmortem, конкретику, ownership и action items, а также широкое распространение знаний о происшествии. :contentReference[oaicite:17]{index=17}

### Postmortem required for

- все `sev1`;
- все `sev2`;
- любой security incident;
- любой инцидент с потерей данных;
- любой инцидент, который повторился;
- любой инцидент по решению Support Lead или Engineering Lead.

### Postmortem sections

- executive summary
- incident date and duration
- impact
- detection
- timeline
- root cause and trigger
- recovery efforts
- what went well
- what went poorly
- where we got lucky
- action items
- owner
- publication date

### Postmortem rules

1. Без обвинительного языка.
2. С конкретными данными, а не эмоциональными формулировками.
3. У каждого action item должен быть owner.
4. У каждого action item должен быть target date.
5. Должен быть link на исходный ticket или incident.
6. Для user-affecting outage должен быть хотя бы один preventive или corrective follow-up.

## Security and Privacy Rules

### Sensitive data minimization

В support domain запрещено без необходимости хранить или повторно выводить:

- полные платёжные реквизиты;
- токены доступа;
- пароли;
- секретные ключи;
- полные документы, не относящиеся к кейсу;
- лишние персональные данные клиента.

### Logging rules

OWASP пишет, что application logging полезен для operational и security use cases, но должен быть осмысленным и безопасным. :contentReference[oaicite:18]{index=18}

Нормативные правила Reva Studio:

1. Не логировать секреты.
2. Маскировать чувствительные идентификаторы, если они не нужны целиком.
3. Логировать actor, tenant, ticket id, action, result, timestamp.
4. Комментарии `internal` не должны попадать в customer-visible responses.
5. Вложения проверяются отдельно от metadata.
6. Любое чтение тикета platform admin должно аудироваться.

## API Error Contract

Для HTTP API домена `support` ошибки должны отдаваться в формате `application/problem+json`, потому что RFC 9457 определяет `problem detail` как стандарт для machine-readable ошибок HTTP API. :contentReference[oaicite:19]{index=19}

### Required fields

- `type`
- `title`
- `status`
- `detail`
- `instance`

### Recommended extension fields

- `code`
- `traceId`
- `ticketId`
- `tenantId`
- `errors`

## Commands

Доменные команды:

- `CreateSupportTicket`
- `TriageSupportTicket`
- `AssignSupportTicket`
- `ReassignSupportTicket`
- `EscalateSupportTicket`
- `AddInternalComment`
- `AddCustomerVisibleComment`
- `AttachFileToTicket`
- `LinkTicketToBooking`
- `LinkTicketToPayment`
- `DeclareIncident`
- `StartMitigation`
- `PauseSLA`
- `ResumeSLA`
- `ResolveSupportTicket`
- `CloseSupportTicket`
- `CancelSupportTicket`
- `CreateProblemRecord`
- `CreatePostmortem`
- `PublishPostmortem`
- `RegisterCorrectiveAction`

## Domain Events

Публикуемые события:

- `support.ticket.created`
- `support.ticket.triaged`
- `support.ticket.assigned`
- `support.ticket.escalated`
- `support.ticket.priority_changed`
- `support.ticket.comment_added`
- `support.ticket.resolved`
- `support.ticket.closed`
- `support.sla.at_risk`
- `support.sla.breached`
- `support.incident.declared`
- `support.incident.mitigated`
- `support.postmortem.required`
- `support.postmortem.published`

Все события обязаны содержать:

- `event_id`
- `event_type`
- `occurred_at`
- `tenant_id` или platform scope marker
- `ticket_id`
- `trace_id`

## Invariants

Нерушимые правила домена:

1. Тикет не может существовать без `ticket_number`.
2. Tenant-scoped тикет не может иметь пустой `tenant_id`.
3. `resolved` невозможен без `resolution_summary`.
4. `closed` невозможен до `resolved`, кроме `cancelled`.
5. `p1` и `p2` incidents не могут закрываться без incident timeline.
6. `internal` comment никогда не может стать `customer_visible` задним числом без отдельного audit event.
7. Attachment metadata обязана принадлежать тому же tenant, что и ticket.
8. Для одного тикета в один момент времени допускается только один активный SLA clock на один metric type.
9. `security_report` нельзя автоматически понижать ниже `p2` без Security Reviewer.
10. `postmortem_required = true` запрещает немедленное финальное закрытие без postmortem linkage.

## Read Models

Поддержка требует отдельных read models:

- `SupportQueueView`
- `SupportAgentWorkloadView`
- `SupportTicketTimelineView`
- `IncidentBridgeView`
- `SupportSLABreachRiskView`
- `TenantSupportOverviewView`
- `PostmortemFollowupView`

## Metrics and KPIs

Внутренние KPI домена:

- first response time
- mean time to mitigate
- mean time to resolve
- reopen rate
- SLA breach rate
- incident recurrence rate
- comment latency
- escalation rate
- customer waiting time
- backlog age
- postmortem completion rate
- corrective action completion rate

Эти метрики являются проектным решением Reva Studio. Их наличие согласуется с внешней идеей structured incident handling и operational logging, но конкретный набор выбран внутренне. :contentReference[oaicite:20]{index=20}

## Integration Boundaries

### With Bookings

Support может:

- ссылаться на booking;
- читать booking status через read model;
- инициировать support-visible compensation workflow.

Support не должен напрямую изменять booking engine, минуя application service.

### With Payments

Support может:

- открыть billing_support ticket;
- ссылаться на payment record;
- запускать проверку состояния платежа.

Support не должен напрямую проводить финансовую операцию без отдельного billing application service.

### With Notifications

Support может:

- инициировать отправку customer update;
- создавать internal escalation notification;
- регистрировать факт отправки.

Support не должен реализовывать delivery transport внутри своего bounded context.

### With Security

Support обязан эскалировать:

- подозрение на компрометацию аккаунта;
- утечку данных;
- подозрительные массовые операции;
- злоупотребление доступами;
- необычные cross-tenant симптомы.

## Recommended Storage Partitioning

Для tenant-scoped таблиц рекомендуются обязательные поля:

- `id`
- `tenant_id`
- `created_at`
- `updated_at`
- `created_by`
- `updated_by`

Для быстрого поиска рекомендуются индексы:

- `(tenant_id, status, priority, created_at desc)`
- `(tenant_id, assigned_agent_id, status)`
- `(tenant_id, ticket_number)`
- `(tenant_id, type, created_at desc)`
- `(tenant_id, resolution_due_at)`
- `(tenant_id, first_response_due_at)`

Это проектная рекомендация Reva Studio, а не внешний факт.

## Minimal Operational Playbooks

Для production-ready работы support должны существовать playbooks, потому что Google SRE отдельно рекомендует актуальные playbooks и обучение on-call команды. :contentReference[oaicite:21]{index=21}

Обязательные playbooks:

- booking outage
- payment reconciliation issue
- telegram delivery outage
- tenant access issue
- data correction request
- массовый сбой интеграции
- security report triage
- SLA breach handling
- incident communications template
- postmortem creation procedure

## Definition of Done

Тикет считается завершённым корректно, если:

1. корректно классифицирован;
2. привязан к tenant;
3. имеет owner;
4. содержит resolution summary;
5. все customer-visible сообщения зафиксированы;
6. audit trail полон;
7. если требовалось, создан postmortem или follow-up;
8. статус переведён в `closed` или `cancelled` по правилам домена.

## Future Extensions

Зарезервированы будущие возможности:

- AI-assisted triage
- duplicate clustering
- sentiment analysis for complaints
- auto-suggested resolution articles
- incident impact estimation
- support quality scoring
- per-tenant support plans
- external customer portal for ticket tracking

## References

1. Microsoft Learn, `Manage incidents and problems in Service Manager`.
2. Google SRE Book, `Incident Management: Key to Restore Operations`.
3. Google SRE Incident Management Guide.
4. Google SRE Workbook, `Postmortem Culture: Learning from Failure`.
5. OWASP Cheat Sheet Series, `Logging Cheat Sheet`.
6. RFC 9457, `Problem Details for HTTP APIs`.