# 0008-risk-controls
# ADR 0008 Risk Controls

Status: Accepted
Date: 2026-02-13
Owner: Security and Risk
Scope: csmarket platform

## Context

csmarket обрабатывает пользовательские действия и операции, связанные с листингом, резервированием, оплатой и выдачей цифровых товаров. Для устойчивости бизнеса и доверия пользователей необходимы риск-контроли, которые:
1) снижают вероятность мошенничества и злоупотреблений
2) ограничивают ущерб при инцидентах
3) обеспечивают трассируемость действий и событий
4) делают безопасность проверяемой через метрики и аудит

Настоящий ADR задает обязательный минимальный набор риск-контролей и требования к их измеримости и проверяемости.

Нормативная опора и методологические источники:
- NIST SP 800-53 Rev. 5 как каталог контролей безопасности и приватности. :contentReference[oaicite:0]{index=0}
- OWASP ASVS как проверяемый набор требований к безопасности приложений. :contentReference[oaicite:1]{index=1}
- CIS Critical Security Controls v8/v8.1 как приоритизированные практики кибергигиены. :contentReference[oaicite:2]{index=2}
- ISO/IEC 27001 как требования к ISMS и управлению безопасностью на уровне организации. :contentReference[oaicite:3]{index=3}

## Key question

Какой обязательный промышленный набор риск-контролей должен быть внедрен в csmarket, чтобы снизить вероятность мошенничества, ошибок и компрометации, и чтобы эти контроли были измеримы, аудитируемы и проверяемы.

## Decision

В csmarket внедряется многоуровневая система риск-контролей:
1) Identity and access controls
2) Transaction and payment controls
3) Fraud and abuse prevention
4) Observability, auditability, and incident response readiness
5) Data protection and secrets management
6) Secure SDLC and continuous verification

Каждый контроль должен иметь:
- owner
- точку внедрения в архитектуре
- критерии успешности
- сигнализацию и метрику
- аудируемый след

## Threat and abuse classes

Минимальные классы рисков, которые должны покрываться контролями:
1) ATO и credential stuffing
2) бот-атаки и массовый scraping
3) подмена параметров операций и обход бизнес-правил
4) мошеннические платежи и возвраты
5) злоупотребление рефералками, бонусами, промокодами
6) злоупотребления со стороны продавцов и покупателей
7) утечки секретов, токенов и ключей
8) инсайдерские действия и ошибки администрирования
9) деградация сервиса, приводящая к финансовым потерям
10) компрометация цепочки поставки зависимостей

Примечание: юридическая квалификация отдельных сценариев зависит от юрисдикции и модели работы. Не могу подтвердить это без конкретной правовой рамки для вашего продукта.

## Controls baseline

### 1) Identity and access

Mandatory:
- MFA для админов и операторов, привилегированные сессии с коротким TTL
- RBAC с принципом наименьших привилегий и раздельностью ролей
- безопасное хранение паролей (современный KDF), защита от перебора
- rate limiting и адаптивные ограничения на login, reset, sensitive endpoints
- device and session controls: ротация refresh tokens, bind to device fingerprint при необходимости
- запрет доступа к admin-функциям без явного audit trail

Verification reference:
- NIST SP 800-53 семейства AC и IA как базис контроля доступа и идентификации. :contentReference[oaicite:4]{index=4}
- OWASP ASVS как основа проверок требований к доступу и аутентификации. :contentReference[oaicite:5]{index=5}

### 2) Transaction and payment controls

Mandatory:
- идемпотентность всех финансово значимых операций (idempotency key)
- строгая валидация входных данных и бизнес-инвариантов на уровне домена
- atomicity: операции учета и статусы должны быть согласованы транзакционно
- двухфазная проверка критичных действий: confirm step или risk-gate для high-risk
- политика лимитов: per-user, per-device, per-time-window для операций с деньгами
- журналирование событий транзакций с неизменяемым следом

Verification reference:
- NIST SP 800-53 семейства AU (audit), SI (integrity), AC (access). :contentReference[oaicite:6]{index=6}
- ISO/IEC 27001 как рамка процессов управления рисками и контролями. :contentReference[oaicite:7]{index=7}

### 3) Fraud and abuse prevention

Mandatory:
- rate limits и bot protections на публичных endpoint-ах
- антифрод-скоринг на уровне правил (rule engine) до ML, с прозрачными причинами
- risk flags: velocity checks, geo and ASN anomalies, disposable emails policy (если используется email)
- защита от злоупотребления промокодами и рефералками: лимиты, связность аккаунтов, cooldown
- блокировка и hold-state для подозрительных операций с ручным разбором (оператор)
- наблюдение за аномалиями по метрикам и алертинг

Verification reference:
- CIS Controls как приоритизация кибергигиены и обнаружения аномалий. :contentReference[oaicite:8]{index=8}
- NIST SP 800-53 как каталог контролей по обнаружению и реагированию через аудит и целостность. :contentReference[oaicite:9]{index=9}

### 4) Observability and auditability

Mandatory:
- audit log для всех admin и финансово значимых действий
- иммутабельность аудита: append-only storage, WORM-подход или удаленная неизменяемая цель
- корреляционные идентификаторы: request id, user id, session id, operation id
- журналы доступа к секретам и ключам
- минимальный набор алертов: всплеск отказов, всплеск логинов, всплеск отмен и возвратов, рост latency
- playbooks инцидентов: критерии, эскалация, SLA на реакцию

Verification reference:
- NIST SP 800-53A как про проверяемость и оценку внедренных контролей, а не чеклисты. :contentReference[oaicite:10]{index=10}
- NIST SP 800-53 семейство AU для аудита. :contentReference[oaicite:11]{index=11}

### 5) Data protection and secrets

Mandatory:
- классификация данных и минимизация собираемых персональных данных
- шифрование в транзите (TLS) и на хранении для чувствительных данных
- централизованный секрет-менеджмент, ротация ключей, запрет секретов в git
- принцип минимально необходимого доступа к данным (need-to-know)
- безопасное удаление и политики retention для логов и данных

Verification reference:
- ISO/IEC 27001 как требования к управлению ISMS и контролям защиты информации. :contentReference[oaicite:12]{index=12}
- CIS Controls как практики управления конфигурациями и секретами в рамках кибергигиены. :contentReference[oaicite:13]{index=13}

### 6) Secure SDLC and continuous verification

Mandatory:
- SAST и dependency scanning на CI, блокировка по критическим уязвимостям
- SBOM для релизов и контроль supply chain
- секрет-сканер в CI
- обязательный code review для security-critical модулей
- тесты безопасности на API: authz, IDOR, rate limit, replay, input validation

Verification reference:
- OWASP ASVS как чек-лист проверяемых требований к безопасности приложения. :contentReference[oaicite:14]{index=14}
- CIS Controls как приоритизация технических мер. :contentReference[oaicite:15]{index=15}

## Metrics and SLOs

Каждый контроль должен иметь метрику. Минимальный набор:
- ATO rate: доля подтвержденных захватов аккаунтов на 10k активных пользователей
- Fraud rate: доля подтвержденных мошеннических операций на 10k операций
- Chargeback and refund anomalies: доля и всплески по времени
- Bot traffic ratio: доля подозрительных запросов
- Auth failures: всплески 401/403 и login failures
- Mean time to detect: время от начала аномалии до алерта
- Mean time to respond: время от алерта до первого действия
- Audit completeness: доля критичных операций с полным audit trail

Не могу подтвердить пороговые значения без ваших исторических данных и бизнес-рисков.

## Enforcement

- Невыполнение обязательных контролей блокирует релиз финансово значимых функций.
- Любой обход контроля оформляется отдельным ADR с risk acceptance и сроком устранения.
- Все исключения имеют owner, expiry date, и проверку на удаление.

## Consequences

Positive:
- Снижение вероятности мошенничества и злоупотреблений
- Прозрачность расследований и аудитируемость
- Меньше финансовых потерь от ошибок и атак

Negative:
- Увеличение сложности и стоимости разработки
- Увеличение времени на внедрение процессов и мониторинга
- Возможные friction для части пользователей из-за лимитов и проверок

## Mapping (high level)

| Control area | NIST SP 800-53 | OWASP ASVS | CIS Controls | ISO 27001 |
|---|---|---|---|---|
| Identity and access | AC, IA | ASVS requirements for auth and access | v8 safeguards mapping | ISMS controls framework |
| Audit and logging | AU | logging requirements | monitoring safeguards | ISMS controls framework |
| Integrity and abuse | SI | input validation requirements | foundational safeguards | ISMS controls framework |
| Verification | 800-53A assessment | ASVS verification basis | prioritized safeguards | ISMS governance |

References:
- NIST SP 800-53 Rev. 5. :contentReference[oaicite:16]{index=16}
- NIST SP 800-53A Rev. 5. :contentReference[oaicite:17]{index=17}
- OWASP ASVS project and v4.0.3 PDF. :contentReference[oaicite:18]{index=18}
- CIS Controls v8 and v8.1. :contentReference[oaicite:19]{index=19}
- ISO/IEC 27001. :contentReference[oaicite:20]{index=20}
