# Incident Response Runbook

Status: Active

Last Updated: 2026-03-23

Owners:
- Security
- Platform
- Backend

Related:
- `docs/architecture/0001-system-overview.md`
- `docs/architecture/0003-tenancy-model.md`
- `docs/architecture/0004-auth-and-rbac.md`
- `docs/architecture/0006-payments-and-ledger.md`
- `docs/domains/tenancy.md`

## 1. Purpose

Этот runbook определяет единый порядок действий при инцидентах безопасности, доступности, целостности данных и платёжных аномалиях в Reva Studio. Его задача:
- быстро подтвердить или опровергнуть инцидент;
- локализовать влияние;
- сохранить доказательства;
- минимизировать ущерб;
- восстановить сервис;
- провести post-incident review и внедрить исправления.

NIST описывает incident handling как процесс подготовки, обнаружения и анализа, containment, eradication, recovery, а также post-incident activity. CISA также использует формальный lifecycle с объявлением инцидента, координацией ответа и восстановлением. :contentReference[oaicite:1]{index=1}

## 2. Scope

Этот runbook применяется к следующим типам инцидентов:
- компрометация учётной записи;
- подозрение на утечку tenant data;
- cross-tenant access;
- компрометация admin credentials;
- аномалии платежей и refund flows;
- нарушение целостности booking/payment/loyalty данных;
- webhook abuse;
- ransomware/malware indicators;
- критическая деградация API, background workers, базы данных, Redis, очередей;
- supply chain и secret exposure incidents;
- уничтожение или отключение логирования и мониторинга.

Не могу подтвердить, что этот документ покрывает все возможные будущие типы инцидентов. Новые классы угроз должны добавляться отдельными обновлениями runbook.

## 3. Principles

1. Safety first.
   Сначала останавливаем продолжающийся ущерб, затем оптимизируем UX.

2. Evidence before cleanup.
   По возможности сначала фиксируем доказательства, затем меняем состояние систем.

3. Least necessary access.
   Любые emergency access действия должны быть ограничены по времени и объёму.

4. One incident commander.
   Во время активной фазы решения координация должна идти через одного ответственного.

5. No silent actions.
   Каждое важное действие должно логироваться в incident timeline.

6. Tenant isolation first.
   При подозрении на cross-tenant exposure приоритетом является подтверждение масштаба и изоляция affected tenant paths.

7. Financial integrity first.
   При платёжных аномалиях нельзя “подправлять” суммы вручную без audit trail и compensating operations.

Эти принципы согласуются с NIST guidance по координированному incident handling, evidence-based analysis и post-incident improvement, а также с практиками log management и security logging. :contentReference[oaicite:2]{index=2}

## 4. Severity Model

### SEV-1 Critical

Критерии:
- подтверждённая или вероятная утечка tenant data;
- подтверждённый cross-tenant access;
- компрометация production admin;
- активная компрометация payment flow;
- массовая недоступность ключевого API;
- разрушение данных без быстрого безопасного отката;
- malware/ransomware indicators на production узле;
- compromise of secrets with active exploitation;
- логирование или мониторинг отключены на production во время подозрительной активности.

Response target:
- acknowledgement: до 15 минут;
- incident commander assigned: до 15 минут;
- containment start: до 30 минут.

### SEV-2 High

Критерии:
- ограниченное нарушение доступности;
- единичный неправомерный доступ без признаков масштабирования;
- подозрение на credential stuffing;
- локальный payment incident без массового затрагивания;
- частичная потеря observability.

Response target:
- acknowledgement: до 30 минут;
- containment start: до 60 минут.

### SEV-3 Medium

Критерии:
- уязвимость без подтверждённой эксплуатации;
- локальная деградация одного модуля;
- повторяющиеся ошибки webhook/retry/reconciliation;
- подозрительные, но неподтверждённые действия.

Response target:
- acknowledgement: до 4 часов.

### SEV-4 Low

Критерии:
- единичные benign-looking alerts;
- noise;
- ложноположительный случай;
- minor policy drift без немедленного риска.

Response target:
- в рабочее время, по плану triage.

NIST и CISA рекомендуют формализованный triage и prioritization, чтобы response зависел от влияния, срочности и масштаба. :contentReference[oaicite:3]{index=3}

## 5. Roles and Responsibilities

### Incident Commander

Отвечает за:
- объявление инцидента;
- принятие решений по containment;
- координацию команд;
- фиксацию статуса;
- закрытие активной фазы.

### Security Lead

Отвечает за:
- анализ признаков компрометации;
- оценку масштаба;
- guidance по evidence preservation;
- рекомендации по credential rotation, isolation и hardening.

### Platform Lead

Отвечает за:
- production runtime;
- сеть;
- контейнеры;
- orchestration;
- секреты;
- rollback/redeploy/failover.

### Backend Lead

Отвечает за:
- API behavior;
- data path;
- migrations;
- queues;
- reconciliation;
- feature toggles.

### Communications Owner

Отвечает за:
- внутренние обновления;
- черновики внешней коммуникации;
- синхронизацию с руководством.

### Scribe

Отвечает за:
- incident timeline;
- журнал решений;
- зафиксированные индикаторы;
- opened questions;
- action items.

## 6. Incident Lifecycle

Основа процесса:
1. Preparation
2. Detection and Analysis
3. Containment
4. Eradication
5. Recovery
6. Post-Incident Activity

Именно такую общую структуру закрепляет NIST в руководстве по incident handling; новая редакция NIST SP 800-61 Rev. 3 также акцентирует встроенность response в общий risk management lifecycle. :contentReference[oaicite:4]{index=4}

## 7. Detection Sources

Источники сигналов:
- application security logs;
- auth logs;
- audit logs;
- payment anomalies;
- reconciliation mismatches;
- webhook verification failures;
- database alerts;
- WAF or reverse proxy signals;
- worker queue anomalies;
- monitoring and alerting;
- user reports;
- bug bounty or responsible disclosure;
- cloud or provider notifications.

NIST SP 800-92 и OWASP Logging Cheat Sheet подчёркивают, что логи должны поддерживать detection, analysis и incident investigation, а security-relevant events должны фиксироваться последовательно и с контекстом. :contentReference[oaicite:5]{index=5}

## 8. Minimum Logging Requirements During an Incident

Во время инцидента обязательно сохранить и при необходимости оперативно экспортировать:
- timestamp в UTC;
- request_id;
- correlation_id;
- actor_id;
- tenant_id;
- source IP;
- user agent;
- target resource;
- action result;
- auth outcome;
- admin actions;
- payment operation identifiers;
- provider event ids;
- queue job ids;
- deployment version;
- host/container identity.

OWASP рекомендует логировать security-relevant события последовательно и с достаточным контекстом, а NIST log management guidance рассматривает логи как критический источник для расследования, корреляции и восстановления картины событий. :contentReference[oaicite:6]{index=6}

## 9. Immediate Triage Checklist

При первом сигнале выполнить:

1. Зафиксировать время обнаружения.
2. Назначить Incident Commander.
3. Открыть incident record.
4. Присвоить preliminary severity.
5. Зафиксировать:
   - источник сигнала;
   - affected service;
   - suspected tenant scope;
   - suspected data types;
   - indicators of compromise;
   - last known good time.
6. Проверить, продолжается ли активная эксплуатация.
7. Проверить, затронуты ли:
   - production secrets;
   - admin accounts;
   - payment provider credentials;
   - database credentials;
   - backups;
   - logging pipeline.
8. Решить, нужен ли emergency containment немедленно.
9. Сохранить volatile evidence до перезапуска, если это безопасно.
10. Начать timeline.

## 10. Evidence Preservation

До любых destructive changes сохранить:
- raw logs;
- audit logs;
- raw webhook events;
- reverse proxy logs;
- database snapshots where feasible;
- container metadata;
- deployment version and commit SHA;
- queue state;
- relevant alerts;
- suspicious requests and headers;
- copies of impacted records before corrective actions.

Правила:
- не редактировать оригинальные evidence artifacts;
- хранить хеши экспортированных файлов;
- отмечать, кто и когда получил доступ;
- все копии складывать в защищённое incident storage;
- не смешивать investigation notes и raw evidence.

NIST подчёркивает важность корректного сбора и анализа incident-related data, а log management guidance отдельно рассматривает необходимость защищённого хранения и целостности логов. :contentReference[oaicite:7]{index=7}

## 11. Containment Strategy

Containment делится на:
- short-term containment;
- long-term containment.

Это соответствует guidance NIST по ограничению ущерба без потери контроля над расследованием. :contentReference[oaicite:8]{index=8}

### 11.1 Short-Term Containment Examples

- отключить компрометированный account;
- revoke active sessions;
- заблокировать API key;
- отключить affected webhook endpoint;
- выключить risky feature flag;
- перевести endpoint в read-only mode;
- временно ограничить admin operations;
- изолировать pod/node/container;
- заблокировать offending IP or CIDR;
- отключить background consumer;
- перевести payment/refund operations в manual approval mode.

### 11.2 Long-Term Containment Examples

- redeploy clean version;
- rotate secrets;
- re-issue service credentials;
- tighten access policies;
- add temporary WAF rules;
- move suspect workload to quarantine environment;
- enforce stronger auth or step-up verification;
- enable extra logging and anomaly monitoring.

## 12. Eradication

После стабилизации определить и удалить root cause:
- удалить malicious code or cron/job hooks;
- убрать несанкционированные accounts/keys;
- закрыть exploited vulnerability;
- удалить вредоносные контейнеры/образы;
- исправить broken authorization checks;
- исправить tenant filters и object-level authorization;
- обновить зависимости;
- удалить persistence mechanisms;
- закрыть exposed storage or admin consoles.

NIST рекомендует после containment устранить причину инцидента перед полноценным восстановлением. :contentReference[oaicite:9]{index=9}

## 13. Recovery

Recovery выполняется поэтапно:
1. восстановить минимально необходимую работоспособность;
2. подтвердить отсутствие продолжающейся компрометации;
3. восстановить нормальные business flows;
4. усилить мониторинг;
5. провести verification window;
6. снять emergency restrictions только после подтверждения.

Во время recovery:
- не возвращать старые secrets;
- не отключать дополнительное логирование слишком рано;
- не завершать инцидент до подтверждения стабилизации.

NIST и CISA выделяют recovery как отдельную управляемую фазу, а не как мгновенный возврат к обычной работе. :contentReference[oaicite:10]{index=10}

## 14. Communication Rules

### Internal Updates

Для SEV-1:
- первичное обновление сразу после объявления;
- далее не реже каждых 30 минут, пока инцидент активен.

Для SEV-2:
- по ключевым изменениям, но не реже чем раз в 60 минут.

Каждое обновление должно содержать:
- severity;
- current status;
- impact;
- affected services;
- containment status;
- current hypotheses;
- next actions;
- owners;
- known unknowns.

### External Communication

Внешние сообщения публикуются только через согласованного owner.
Нельзя:
- обещать неподтверждённые сроки;
- утверждать причину без подтверждения;
- занижать масштаб;
- публиковать технические детали, которые увеличивают риск эксплуатации до завершения containment.

Не могу подтвердить юридические обязательства по уведомлению для конкретной юрисдикции без отдельного анализа применимого права.

## 15. Decision Matrix

### Stop the world decisions

Немедленно допускаются при:
- подтверждённой утечке tenant data;
- активной эксплуатации admin access;
- compromise of payment/refund path;
- активном destructive write path;
- ransomware indicators;
- confirmed cross-tenant read/write.

### Continue with monitoring

Допускается только если:
- сигнал низкой уверенности;
- нет подтверждённого вреда;
- containment already in place;
- риск дальнейшего ущерба ниже риска аварийной остановки.

## 16. Service-Specific Playbooks

### 16.1 Suspected Cross-Tenant Access

Признаки:
- пользователь видит чужие bookings/customers/payments;
- mismatched tenant_id в логах;
- object returned without tenant predicate;
- RLS or authorization anomaly;
- support ticket with чужими данными в интерфейсе.

Действия:
1. Объявить не ниже SEV-1, если exposure подтверждён.
2. Заморозить affected endpoint or query path.
3. Включить усиленное логирование по affected resources.
4. Экспортировать:
   - request logs;
   - authorization decisions;
   - SQL traces if available;
   - audit logs;
   - access history affected object ids.
5. Определить:
   - first seen;
   - affected tenants;
   - data classes;
   - read vs write scope.
6. Проверить последние deploys, feature flags, migrations.
7. Если причина в broken auth filter:
   - hotfix;
   - regression test;
   - backfill access review.
8. Провести customer impact analysis.
9. Подготовить list of exposed records.
10. Не возобновлять endpoint до:
   - fixed code;
   - verified tests;
   - monitored canary behavior.

### 16.2 Admin Account Compromise

Признаки:
- admin login from unusual source;
- unexpected role changes;
- suspicious exports;
- refund/adjustment actions without business reason;
- credential reset anomalies.

Действия:
1. Disable or lock affected admin account.
2. Revoke sessions and API tokens.
3. Rotate related secrets if access might have reached them.
4. Review admin audit log.
5. Identify actions performed after suspected compromise time.
6. Check data exports, refunds, pricing changes, staff changes, feature toggles.
7. Require password reset and stronger auth controls.
8. Restore unauthorized changes through auditable compensating actions.

### 16.3 Payment Incident

Признаки:
- duplicate charges;
- refunds without request;
- failed reconciliation;
- webhook replay anomalies;
- provider credential suspicion;
- mismatch between provider state and internal ledger.

Действия:
1. Freeze risky payment mutations if needed.
2. Preserve:
   - provider event payloads;
   - idempotency records;
   - payment attempts;
   - ledger entries;
   - outbox events.
3. Distinguish:
   - provider-side anomaly;
   - internal posting anomaly;
   - duplicate request handling failure;
   - reconciliation delay.
4. Validate affected scope:
   - payment ids;
   - refund ids;
   - tenants;
   - amounts;
   - time window.
5. For internal data correction:
   - no destructive edits;
   - use compensating operations only.
6. If provider credentials suspected:
   - rotate immediately;
   - verify webhook secrets;
   - audit recent provider actions.
7. Reconcile all affected payments before incident closure.

### 16.4 Data Integrity Incident

Признаки:
- missing bookings;
- impossible balances;
- orphaned records;
- out-of-order state transitions;
- audit trail mismatch.

Действия:
1. Stop automated writers touching affected domain.
2. Snapshot current data state.
3. Identify last known good state.
4. Review recent migrations, jobs, manual operations, repair scripts.
5. Build correction plan:
   - restore from backup;
   - replay outbox/events;
   - compensating writes;
   - manual verified repair.
6. All repair actions must be logged and peer-reviewed.

### 16.5 Webhook Abuse or Replay

Признаки:
- repeated delivery with unexpected frequency;
- invalid signatures;
- mismatched provider event ids;
- processing storms;
- unexpected state changes after webhook processing.

Действия:
1. Check signature verification path.
2. Confirm dedup logic.
3. Temporarily pause consumer if replay causes state churn.
4. Export raw events and processing history.
5. Verify no event applied more than once.
6. Re-run reconciliation.
7. Rotate webhook secret if compromise suspected.

CISA and NIST both emphasize controlled response workflows and verified recovery, while provider-integrated systems require strong handling of event ingestion and retries. :contentReference[oaicite:11]{index=11}

## 17. Secrets and Credential Rotation

Rotate immediately when relevant:
- admin passwords;
- session signing keys if session forgery risk exists;
- JWT signing keys if token trust is at risk;
- database credentials;
- Redis credentials;
- queue credentials;
- payment provider keys;
- webhook secrets;
- cloud access keys;
- SMTP/API integration secrets.

OWASP notes that incident response often depends on fast and reliable access to secrets and credentials needed for recovery actions. :contentReference[oaicite:12]{index=12}

Правила:
- rotation plan должен фиксировать affected services;
- сначала выпустить новые credentials, затем revoke old;
- после rotation провести restart/redeploy affected services;
- проверить, что старые credentials реально недействительны.

## 18. Backups and Restore

При инцидентах целостности и разрушения данных:
1. Подтвердить, что backup не содержит уже компрометированное состояние, если инцидент длился долго.
2. Проверить restore в isolated environment.
3. Сравнить:
   - data loss window;
   - reconciliation gap;
   - side effects after backup timestamp.
4. Выполнять restore только по утверждённому plan of record.
5. После restore:
   - run integrity checks;
   - replay safe events where required;
   - audit access and mutations.

Не могу подтвердить конкретные RPO/RTO без отдельного документа по backup policy Reva Studio.

## 19. Monitoring During Active Incident

На время активного инцидента включить:
- higher log retention for affected paths;
- targeted alerts;
- suspicious auth monitoring;
- high-cardinality tracing only where safe;
- request sampling override for affected endpoints;
- queue depth monitoring;
- DB error rate monitoring;
- rate of denied authorization;
- payment/refund anomaly dashboards.

NIST SP 800-92 и OWASP Logging Cheat Sheet поддерживают идею целевого усиления logging and analysis practices для расследования и корреляции событий. :contentReference[oaicite:13]{index=13}

## 20. Incident Record Template

Каждый инцидент обязан иметь record со следующими полями:

- Incident ID
- Title
- Severity
- Status
- Incident Commander
- Scribe
- Detected at UTC
- Declared at UTC
- Source of detection
- Affected systems
- Affected tenants
- Affected data classes
- Summary
- Initial indicators
- Containment actions
- Evidence links
- Root cause
- Eradication actions
- Recovery actions
- Customer impact
- Regulatory or contractual review required
- Lessons learned
- Follow-up actions
- Closed at UTC

## 21. Timeline Template

Каждая запись timeline:
- UTC timestamp
- actor
- action
- system or resource
- evidence reference
- outcome
- next step

Пример:
- `2026-03-23T11:04:12Z`
- `platform-oncall`
- `revoked payment webhook secret`
- `stripe-webhook-prod`
- `evidence://incident/IR-2026-004/secret-rotation-log`
- `success`
- `restart webhook consumers`

## 22. Exit Criteria for Active Phase

Активная фаза incident response может быть закрыта, только если:
1. containment завершён;
2. root cause устранён или надёжно нейтрализован;
3. recovery завершён;
4. monitoring confirms stability;
5. scope and impact documented;
6. evidence preserved;
7. required rotations completed;
8. customer/business impact assessed;
9. follow-up actions opened;
10. Incident Commander formally closes active phase.

## 23. Post-Incident Review

NIST explicitly includes post-incident activity and lessons learned as a required part of incident handling. :contentReference[oaicite:14]{index=14}

Провести не позднее 5 рабочих дней после closure.

Обязательные вопросы:
1. Что случилось?
2. Как мы узнали?
3. Когда началось фактически?
4. Что не сработало в detection?
5. Что замедлило containment?
6. Какие данные или деньги были затронуты?
7. Какие решения были правильными?
8. Какие решения были ошибочными?
9. Что нужно автоматизировать?
10. Какие тесты, алерты, runbooks, архитектурные ограничения надо добавить?

Выходы postmortem:
- root cause summary;
- timeline;
- contributing factors;
- control gaps;
- remediation backlog;
- owner and due date per action;
- decision on customer-facing communication if required.

## 24. Mandatory Follow-Up Actions

После каждого SEV-1 и SEV-2:
- добавить regression tests;
- обновить detection rules;
- обновить dashboards and alerts;
- обновить runbook if needed;
- пересмотреть access model;
- пересмотреть secret rotation coverage;
- убедиться, что lessons learned внедрены, а не только записаны.

## 25. Reva Studio Production Rules

1. Никаких silent hotfixes без incident record при SEV-1/SEV-2.
2. Никаких ручных исправлений платежей без compensating audit trail.
3. Никаких destructive cleanup действий до evidence capture, если это безопасно.
4. Никаких предположений о масштабе без проверки логов и affected records.
5. Никаких cross-tenant incident closures без явной tenant impact review.
6. Никаких восстановлений из backup без integrity verification.
7. Никаких отключений security logging без одобрения Incident Commander.
8. Никаких untracked credential rotations.
9. Никаких внешних заявлений без согласованного owner.
10. Никакого закрытия инцидента без post-incident action list.

## 26. Quick Command Checklist

### First 15 Minutes

- declare incident
- assign incident commander
- open incident record
- set severity
- preserve evidence
- identify scope
- decide containment
- notify core responders

### First 60 Minutes

- complete initial triage
- isolate affected path
- rotate obviously exposed credentials
- export relevant logs
- confirm impact hypothesis
- start timeline
- define recovery gate

### Before Closure

- containment verified
- root cause documented
- recovery verified
- evidence stored
- impact assessed
- follow-up actions opened
- postmortem scheduled

## 27. References

1. NIST SP 800-61 Rev. 2, Computer Security Incident Handling Guide. :contentReference[oaicite:15]{index=15}
2. NIST SP 800-61 Rev. 3, Incident Response Recommendations and Considerations for Cybersecurity Risk Management. :contentReference[oaicite:16]{index=16}
3. CISA, Cybersecurity Incident & Vulnerability Response Playbooks. :contentReference[oaicite:17]{index=17}
4. NIST SP 800-92, Guide to Computer Security Log Management. :contentReference[oaicite:18]{index=18}
5. OWASP Logging Cheat Sheet. :contentReference[oaicite:19]{index=19}
6. OWASP Secrets Management Cheat Sheet. :contentReference[oaicite:20]{index=20}

## 28. Source Notes

Подтверждённые внешними источниками тезисы:
- incident response строится вокруг формального lifecycle;
- detection, analysis, containment, eradication, recovery и post-incident activity являются базовыми стадиями;
- логи критичны для анализа и расследования;
- security logging должно быть последовательным и контекстным;
- credential and secret handling важны для response and recovery.

Внутренние решения Reva Studio:
- конкретная severity model;
- response targets;
- роли Incident Commander, Security Lead и Scribe;
- product-specific playbooks;
- шаблоны incident record и timeline;
- production rules and closure gates.

Эти внутренние части являются архитектурой и операционной политикой Reva Studio, а не внешними фактами.