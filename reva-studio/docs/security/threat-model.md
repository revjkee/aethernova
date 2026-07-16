# Threat Model

## Статус документа

- Статус: Accepted
- Проект: Reva Studio
- Раздел: Security
- Подраздел: Threat Modeling
- Уровень: Platform / Product
- Классификация: Internal Sensitive
- Версия: 1.0.0
- Последнее обновление: 2026-03-23
- Владельцы: Security, Backend, DevOps, Platform

---

## 1. Назначение документа

Этот документ фиксирует промышленную модель угроз для Reva Studio и определяет:

- защищаемые активы;
- границы доверия;
- ключевые сценарии атак;
- вероятные векторы компрометации;
- обязательные меры снижения риска;
- требования к мониторингу, аудиту и реагированию;
- правила пересмотра модели угроз при изменении архитектуры.

Документ предназначен для:

- архитекторов;
- backend-разработчиков;
- DevOps и platform engineering;
- специалистов по безопасности;
- владельцев продукта;
- команды эксплуатации.

---

## 2. Методологическая база

Данная модель угроз построена на сочетании следующих подходов:

- asset-centric analysis;
- trust boundary analysis;
- data flow analysis;
- STRIDE-классификации угроз;
- risk-based prioritization;
- mapping to security controls.

В качестве внешней проверяемой основы используются:

- подход OWASP Threat Modeling;
- рекомендации OWASP Threat Modeling Cheat Sheet;
- контрольные требования OWASP ASVS;
- практики Secure Software Development Framework от NIST;
- матрица MITRE ATT&CK для сопоставления сценариев противника.

---

## 3. Область действия

В область действия этой модели входят:

- Telegram bot layer;
- backend API;
- admin panel;
- authentication and authorization;
- booking workflows;
- loyalty workflows;
- notification workflows;
- payments integration layer;
- database and cache layers;
- background workers and schedulers;
- observability stack;
- secrets and configuration management;
- CI/CD and deployment pipeline;
- infrastructure perimeter and service-to-service trust.

В область действия не входят:

- физическая безопасность офиса;
- безопасность устройств клиентов вне границ продукта;
- безопасность внешних провайдеров как таковых, кроме интеграционных рисков для Reva Studio;
- юридическая оценка договоров с провайдерами.

---

## 4. Контекст системы

Reva Studio представляет собой платформу для управления beauty-бизнесом с Telegram-ориентированным пользовательским контуром и backend-платформой, включающей:

- клиентский Telegram-бот;
- административный интерфейс;
- API-сервисы;
- фоновую обработку задач;
- БД и кэш;
- интеграции с внешними провайдерами;
- подсистему уведомлений;
- подсистему лояльности;
- журналирование, метрики и аудит.

---

## 5. Цели безопасности

Безопасность системы должна обеспечивать:

- конфиденциальность персональных данных клиентов и сотрудников;
- целостность записей, бонусов, платежных статусов и системных событий;
- доступность клиентских и административных функций;
- подлинность субъектов и действий;
- трассируемость критических операций;
- устойчивость к повторной обработке, злоупотреблению и ошибкам интеграции;
- управляемость инцидентов и способность к forensic-разбору.

---

## 6. Ключевые активы

### 6.1 Данные высокой критичности

- учетные данные администраторов;
- токены бота и интеграционные секреты;
- сессионные и refresh-токены;
- персональные данные клиентов;
- контактные данные клиентов и мастеров;
- история записей;
- бонусный баланс и операции лояльности;
- статусы оплат и связанные идентификаторы транзакций;
- внутренние журналы безопасности;
- конфигурация окружения;
- резервные копии.

### 6.2 Данные средней критичности

- шаблоны уведомлений;
- расписания мастеров;
- каталоги услуг;
- аналитические агрегаты;
- operational logs без чувствительных данных.

### 6.3 Технические активы

- API endpoints;
- admin endpoints;
- message queues;
- worker execution context;
- PostgreSQL;
- Redis;
- CI/CD runners;
- container registry;
- ingress / reverse proxy;
- observability endpoints;
- secret stores.

---

## 7. Предположения и ограничения

1. Telegram является одним из основных пользовательских каналов взаимодействия, но не должен считаться доверенной средой по умолчанию.
2. Внешние интеграции потенциально ненадежны и могут давать ошибки, задержки, дубликаты и неконсистентные ответы.
3. Внутренний периметр не считается полностью безопасным.
4. Любой сервисный аккаунт рассматривается как потенциальная точка компрометации.
5. Любая операция, влияющая на деньги, бонусы, доступы или персональные данные, требует повышенного уровня контроля.
6. Любая асинхронная обработка рассматривается как источник риска повторов, рассинхронизации и race conditions.
7. Любой административный интерфейс является высокоценной целью.

---

## 8. Акторы угроз

### 8.1 Внешний злоумышленник

Цели:

- захват аккаунта администратора;
- получение персональных данных;
- эксплуатация публичного API;
- abuse бонусной системы;
- эксплуатация логики записи и отмен;
- массовая рассылка через систему;
- отказ в обслуживании.

### 8.2 Недобросовестный пользователь

Цели:

- искусственное получение бонусов;
- обход ограничений на записи и отмены;
- злоупотребление промокодами;
- перебор параметров API;
- попытка доступа к чужим данным.

### 8.3 Компрометированный интеграционный провайдер или ключ

Цели:

- отправка ложных callback-событий;
- подмена статуса оплаты;
- внедрение вредоносного payload;
- утечка секретов;
- replay внешних событий.

### 8.4 Внутренний нарушитель

Цели:

- несанкционированный просмотр клиентских данных;
- изменение баланса лояльности;
- экспорт баз данных;
- отключение журналирования;
- обход бизнес-правил через админку.

### 8.5 Автоматизированный бот / массовый сканер

Цели:

- credential stuffing;
- сканирование уязвимых эндпоинтов;
- abuse rate-limited операций;
- вызов деградации сервиса.

---

## 9. Архитектурные зоны и границы доверия

### 9.1 Внешняя зона

- Telegram platform;
- браузеры клиентов;
- устройства сотрудников;
- внешние API провайдеров;
- интернет-трафик.

### 9.2 Пограничная зона

- ingress / reverse proxy;
- webhook endpoints;
- public REST API;
- admin login endpoints.

### 9.3 Внутренняя сервисная зона

- application services;
- background workers;
- scheduler;
- internal event handlers.

### 9.4 Зона данных

- PostgreSQL;
- Redis;
- object storage;
- backups;
- audit storage.

### 9.5 Зона управления

- CI/CD;
- secrets management;
- observability;
- deployment control plane;
- admin console.

Основные trust boundaries:

- между интернетом и ingress;
- между Telegram/provider callbacks и backend;
- между public API и internal services;
- между app services и database;
- между workers и queue;
- между admin users и privileged endpoints;
- между CI/CD and runtime infrastructure;
- между logs/metrics/traces and privileged data.

---

## 10. Поверхности атаки

Ключевые attack surfaces:

- webhook endpoints;
- authentication endpoints;
- token refresh endpoints;
- admin endpoints;
- public booking endpoints;
- loyalty mutation endpoints;
- notification dispatch logic;
- file upload or media handling;
- provider callback handlers;
- queue consumers;
- cron/scheduler flows;
- observability dashboards;
- misconfigured storage buckets;
- secrets in environment variables;
- deployment pipeline;
- debug and health endpoints.

---

## 11. Главные сценарии угроз по STRIDE

## 11.1 Spoofing

### Угрозы

- подделка webhook/callback запроса;
- захват сессии администратора;
- использование украденного Telegram binding;
- подделка внутреннего сервисного вызова;
- использование похищенного service token;
- impersonation клиента через подбор идентификаторов.

### Риски

- несанкционированное изменение записей;
- ложные изменения статусов оплат;
- компрометация loyalty операций;
- доступ к персональным данным;
- отправка несанкционированных уведомлений.

### Меры

- обязательная проверка подписи или секрета callback-провайдера;
- короткоживущие токены доступа;
- строгая валидация audience, issuer, expiry и subject;
- ротация токенов и секретов;
- service-to-service authentication;
- привязка Telegram identity к внутреннему user binding через подтвержденный flow;
- MFA для admin-контура;
- защита от session fixation;
- re-auth для высокорисковых операций.

---

## 11.2 Tampering

### Угрозы

- изменение payload в транзите;
- подмена параметров запроса;
- изменение бонусного баланса вне доменной логики;
- изменение статусов записи или оплаты;
- массовая правка шаблонов уведомлений;
- модификация логов или аудита;
- tampering миграций или CI/CD артефактов.

### Риски

- финансовый ущерб;
- некорректные записи;
- ложные уведомления;
- потеря доверия клиентов;
- скрытие следов атаки.

### Меры

- TLS для внешнего трафика;
- строгая серверная валидация всех входных данных;
- RBAC и least privilege;
- optimistic locking или иные меры целостности для конкурентных обновлений;
- append-only audit для критических действий;
- checksum/signature verification для build artifacts;
- change approval для production deployments;
- immutable logs там, где это допустимо архитектурой;
- строгая доменная изоляция операций изменения баланса и статусов.

---

## 11.3 Repudiation

### Угрозы

- пользователь или сотрудник отрицает выполнение действия;
- администратор скрывает изменение записи, бонусов или уведомлений;
- отсутствие корреляции между событием и инициатором;
- отключение журналирования при инциденте.

### Риски

- невозможность расследования;
- невозможность доказать злоупотребление;
- юридические и операционные риски;
- потеря управляемости.

### Меры

- обязательный audit trail для критических операций;
- correlation_id и causation_id;
- actor_id для действий из admin-контура;
- tamper-evident хранение журналов, где возможно;
- журналирование не только ошибок, но и security-sensitive success events;
- разграничение operational logs и security logs;
- отдельный доступ к журналам по RBAC.

---

## 11.4 Information Disclosure

### Угрозы

- утечка PII через API;
- утечка секретов через логи;
- раскрытие данных через debug endpoints;
- IDOR и broken access control;
- раскрытие персональных данных через админку;
- ошибочный экспорт аналитики;
- утечка резервных копий;
- exposure через observability stack;
- избыточно подробные ошибки;
- секреты в CI/CD output.

### Риски

- компрометация клиентов и сотрудников;
- регуляторные последствия;
- захват интеграций;
- reputational damage.

### Меры

- data minimization;
- masking/redaction в логах;
- object-level authorization;
- deny-by-default на admin и internal resources;
- отключение debug в production;
- encryption in transit;
- контроль доступа к backup и dump-файлам;
- секреты только через секрет-хранилище или контролируемые механизмы доставки;
- review структуры ответов API;
- hardening observability endpoints.

---

## 11.5 Denial of Service

### Угрозы

- массовая отправка запросов на публичные endpoints;
- флуд webhook endpoints;
- перегрузка очередей;
- исчерпание пулов соединений;
- тяжёлые query patterns;
- storms от retry loops;
- злоупотребление уведомлениями;
- блокировка worker pool через длительные задачи.

### Риски

- недоступность записи;
- задержки уведомлений;
- деградация админки;
- cascading failure;
- потеря бизнес-операций.

### Меры

- rate limiting;
- concurrency limits;
- timeouts;
- circuit breakers;
- backpressure;
- bounded retries с jitter;
- приоритеты очередей;
- graceful degradation;
- separate pools для критичных и некритичных задач;
- query optimization и индексы;
- auto-scaling, где допустимо архитектурой.

---

## 11.6 Elevation of Privilege

### Угрозы

- escalation из user в admin;
- обход RBAC через некорректные проверки;
- использование служебных endpoints без нужной роли;
- чрезмерные права service accounts;
- privilege escalation через CI/CD;
- доступ worker к избыточным секретам;
- использование insecure defaults.

### Риски

- полный захват системы;
- массовая утечка данных;
- подмена платежных и бонусных операций;
- скрытая компрометация.

### Меры

- role separation;
- least privilege;
- fine-grained authorization;
- policy enforcement на уровне application service;
- секреты по принципу need-to-know;
- отдельные сервисные аккаунты по bounded context;
- регулярный review ролей;
- запрет shared admin accounts;
- approval и separation of duties для production actions.

---

## 12. Приоритетные abuse cases

### AC-01. Начисление бонусов повторной обработкой события
Описание:
Злоумышленник или ошибка интеграции вызывает повторную обработку одного и того же события, связанного с loyalty.

Риски:
- незаконное начисление бонусов;
- расхождение баланса;
- финансовый ущерб.

Контрмеры:
- идемпотентные ключи;
- уникальные ограничения на уровне БД;
- outbox/inbox pattern там, где это применимо;
- audit trail всех операций баланса;
- reconciliation jobs.

### AC-02. Подмена callback статуса оплаты
Описание:
На endpoint callback приходит ложный запрос с успешным статусом.

Контрмеры:
- подпись или секрет callback;
- allowlist источников, если применимо;
- повторная server-side verification статуса у провайдера;
- идемпотентность обработки;
- state machine для допустимых переходов статусов.

### AC-03. Захват admin-аккаунта
Описание:
Атакующий получает доступ к административной панели.

Контрмеры:
- MFA;
- защита сессии;
- ограничение по ролям;
- re-auth на критические действия;
- алерты на необычные логины;
- audit всех админских операций;
- IP/device risk signals, если доступны.

### AC-04. Массовая отправка сообщений через notification subsystem
Описание:
Злоумышленник получает возможность инициировать несанкционированные уведомления.

Контрмеры:
- строгий контроль команд на отправку;
- template allowlist;
- rate limits;
- approval flow для массовых кампаний;
- журналирование инициатора;
- kill switch на уровне провайдера и приложения.

### AC-05. Получение чужих данных через IDOR
Описание:
Пользователь изменяет идентификаторы объектов в API и получает доступ к чужим данным.

Контрмеры:
- object-level authorization;
- не полагаться на client-supplied ownership;
- тесты на broken access control;
- review всех list/detail endpoints.

### AC-06. Компрометация CI/CD
Описание:
Через pipeline внедряется вредоносный код или утечка секретов.

Контрмеры:
- защищенные секреты CI/CD;
- branch protection;
- required reviews;
- artifact provenance checks;
- минимизация прав runner;
- отдельные окружения и approvals для production.

---

## 13. Наиболее критичные технические угрозы

1. Broken access control.
2. Compromised admin credentials.
3. Replay и дублирование внешних событий.
4. Несанкционированные изменения loyalty balance.
5. Подмена или повторная доставка callback-платежей.
6. Утечка секретов через конфиги, логи или CI/CD.
7. Queue storms и uncontrolled retries.
8. Notification abuse.
9. Компрометация service accounts.
10. Неполный аудит критичных операций.

---

## 14. Контроли безопасности по слоям

## 14.1 Identity and Access

- MFA для административного контура;
- strong password policy;
- account lockout / throttling;
- refresh token rotation;
- session invalidation;
- RBAC;
- least privilege;
- service identity isolation;
- periodic access review.

## 14.2 Application Layer

- строгая schema validation;
- canonical input validation;
- output encoding там, где есть отображение;
- object-level authorization;
- CSRF protection для web admin при cookie-based flows;
- secure headers для admin UI;
- ограничение на upload types и размеры;
- безопасная обработка ошибок без лишних деталей;
- идемпотентность для критичных мутаций.

## 14.3 Data Layer

- параметризованные запросы;
- миграции через контролируемый pipeline;
- защита backup;
- шифрование каналов до БД;
- строгие DB roles;
- минимальные DB grants;
- контроль целостности критичных таблиц;
- разделение operational и audit data.

## 14.4 Async and Queue Layer

- deduplication keys;
- retry budget;
- DLQ;
- queue partitioning по критичности;
- visibility timeout и timeout control;
- защита от poison messages;
- bounded consumer concurrency.

## 14.5 Infrastructure Layer

- hardening контейнеров и образов;
- минимальные base images;
- non-root execution, где возможно;
- network segmentation;
- защищенный ingress;
- secrets management;
- запрет debug interfaces в production;
- ограничение доступа к observability и admin tools.

## 14.6 CI/CD Layer

- signed or verified artifacts, если внедрено;
- protected branches;
- mandatory code review;
- secret scanning;
- dependency scanning;
- environment separation;
- manual approval для production;
- ограниченный доступ к deployment credentials.

---

## 15. Требования к логированию и аудиту

Обязательно журналируются:

- попытки входа и отказа во входе;
- выдача, обновление и отзыв токенов;
- административные действия;
- операции изменения бонусного баланса;
- операции изменения ролей и прав;
- операции изменения шаблонов уведомлений;
- callback failures и callback verification failures;
- security-sensitive configuration changes;
- блокировки, throttling и rate-limit triggers;
- критичные ошибки очередей и retry exhaustion.

В каждом журналируемом событии должны быть, где применимо:

- timestamp;
- actor_id;
- actor_type;
- tenant_id;
- correlation_id;
- request_id;
- source_ip;
- target_resource;
- action;
- result;
- reason_code.

Запрещено логировать:

- пароли;
- полные секреты;
- полные токены;
- лишние персональные данные;
- чувствительные данные платежного провайдера сверх необходимого минимума.

---

## 16. Требования к мониторингу и детектированию

Минимальные детектируемые события:

- всплеск login failures;
- всплеск 401/403;
- рост callback verification failures;
- рост duplicate event suppressions;
- аномальный рост начислений бонусов;
- массовые admin mutations;
- необычная активность service accounts;
- spikes по queue lag;
- рост DLQ;
- резкий рост notification dispatch;
- рост error rate на провайдерах;
- изменение критичных секретов и конфигураций;
- отключение или деградация security logging.

---

## 17. Требования к secure SDLC

Изменения в продукте должны сопровождаться:

- пересмотром модели угроз при изменении trust boundary;
- пересмотром модели угроз при добавлении нового внешнего провайдера;
- пересмотром модели угроз при добавлении нового privileged workflow;
- security review новых admin-возможностей;
- тестами на authorization для новых endpoints;
- проверкой идемпотентности критичных мутаций;
- review логирования и redaction;
- review новых секретов и их пути доставки;
- проверкой rollback и incident response impact.

---

## 18. Приоритетная матрица рисков

### R1. Компрометация admin-контура
- Вероятность: High
- Влияние: Critical
- Приоритет: P0

### R2. Broken access control / IDOR
- Вероятность: High
- Влияние: Critical
- Приоритет: P0

### R3. Replay внешних событий и двойная обработка
- Вероятность: High
- Влияние: High
- Приоритет: P0

### R4. Несанкционированное изменение loyalty balance
- Вероятность: Medium
- Влияние: Critical
- Приоритет: P0

### R5. Утечка секретов из runtime или CI/CD
- Вероятность: Medium
- Влияние: Critical
- Приоритет: P0

### R6. Массовый abuse notification subsystem
- Вероятность: Medium
- Влияние: High
- Приоритет: P1

### R7. Queue-based DoS и retry storms
- Вероятность: Medium
- Влияние: High
- Приоритет: P1

### R8. Компрометация observability/admin tooling
- Вероятность: Medium
- Влияние: High
- Приоритет: P1

---

## 19. Обязательные security requirements для реализации

### P0

- MFA для admin.
- RBAC с deny-by-default.
- Object-level authorization для клиентских и административных объектов.
- Идемпотентность для loyalty, payment callbacks и критичных async-команд.
- Проверка подлинности внешних callbacks.
- Безопасное хранение и ротация секретов.
- Security audit trail.
- Rate limiting на public endpoints.
- Маскирование чувствительных данных в логах.
- Разделение ролей и сервисных аккаунтов.
- Review и hardening CI/CD.

### P1

- Детектирование аномалий по бонусам и уведомлениям.
- DLQ и retry governance.
- Контроль массовых операций из админки.
- Повышенный мониторинг admin действий.
- Регулярный review прав и секретов.
- Hardening observability surfaces.

### P2

- Расширенные threat simulations.
- Регулярное tabletop exercise по incident response.
- Coverage mapping на ATT&CK / ASVS.
- Автоматизация drift detection в security-конфигурации.

---

## 20. Проверочные вопросы перед релизом

1. Появилась ли новая trust boundary?
2. Появился ли новый внешний провайдер?
3. Появился ли новый privileged endpoint?
4. Есть ли новая операция с деньгами, бонусами или персональными данными?
5. Есть ли новые async consumer flows?
6. Может ли новое событие обрабатываться повторно?
7. Может ли новый endpoint привести к IDOR или privilege escalation?
8. Не утекают ли чувствительные данные в логи, traces, metrics?
9. Есть ли audit trail для новой критичной операции?
10. Есть ли rollback и kill switch для новой интеграции?

---

## 21. Минимальный план верификации

- Проверка authorization matrix.
- Проверка tenant isolation.
- Проверка object ownership enforcement.
- Проверка callback authentication.
- Проверка replay resistance.
- Проверка idempotency ключей и уникальных ограничений.
- Проверка rate limiting.
- Проверка redaction в логах.
- Проверка admin audit trail.
- Проверка DLQ и retry behavior.
- Проверка доступа к observability.
- Проверка секретов в CI/CD и runtime.

---

## 22. Условия пересмотра threat model

Threat model должен пересматриваться при любом из событий:

- новый канал интеграции;
- новый способ аутентификации;
- новая admin-функция;
- новая очередь или background workflow;
- новый provider callback;
- изменение модели ролей;
- изменение схемы хранения чувствительных данных;
- инцидент безопасности;
- существенная смена архитектуры деплоя;
- ввод multi-tenant режима или изменение tenant isolation.

---

## 23. Итоговое решение

Для Reva Studio принимается следующая позиция:

- система рассматривается как находящаяся в hostile-by-default среде;
- доверие не передается автоматически между зонами;
- административный контур и loyalty/payment workflows считаются зонами максимального риска;
- все внешние события и callbacks считаются потенциально поддельными до успешной проверки;
- все критичные мутации должны быть идемпотентны, аудируемы и ограничены авторизацией;
- все изменения архитектуры обязаны инициировать пересмотр модели угроз.

---

## 24. Контрольное сопоставление с внешними практиками

Эта модель угроз согласована по смыслу со следующими внешними практиками:

- подходом OWASP threat modeling с вопросами: что мы строим, что может пойти не так, что мы делаем по этому поводу, и достаточно ли этого;
- рекомендацией OWASP рассматривать декомпозицию приложения, идентификацию и ранжирование угроз, меры снижения риска и review/validation;
- использованием OWASP ASVS как основы для проверки технических security controls;
- практиками NIST SSDF по интеграции security в SDLC;
- использованием MITRE ATT&CK как базы знаний по реальным техникам противника.

---

## 25. Источники

### OWASP
- OWASP Threat Modeling Process
- OWASP Threat Modeling Cheat Sheet
- OWASP Threat Modeling Project
- OWASP ASVS

### NIST
- NIST Secure Software Development Framework, SP 800-218

### MITRE
- MITRE ATT&CK Enterprise Tactics
- MITRE ATT&CK Resources

---