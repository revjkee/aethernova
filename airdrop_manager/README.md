# airdrop_manager/README.md

# Airdrop Manager

Airdrop Manager — промышленный модуль оркестрации дистрибуции токенов и цифровых активов для Web3/FinTech-экосистем: планирование, верификация,
антифрод, идемпотентная рассылка, аудит и наблюдаемость. Поддерживает pull- и push-модель, off-chain очереди, on-chain подтверждения, многоцепочечность и dry-run.

## Ключевые возможности

- Идемпотентные выплаты: устойчивость к ретраям, дедупликация по `payout_id` и ончейн-tx hash.
- Антифрод и комплаенс-гейты: allow/deny-листы, санкционные списки, velocity-лимиты, гео-ограничения, KYC-флаги.
- Планировщик кампаний: батчинги по окнам, fair-queue, приоритеты.
- Многоцепочечность: абстракция провайдеров (EVM, TON, Solana и др.) через единый интерфейс драйверов.
- Наблюдаемость: метрики, логи, трассировка, события в JSONL для судебного аудита.
- Безопасность: подписи транзакций в HSM/валт-изоляте, ротация ключей, разделение ролей.
- Восстановление: идемпотентные повторные прогоны, компенсирующие операции, снапшоты состояния кампаний.
- Режимы выполнения: synchronous, async-batch, dry-run, canary, shadow.

## Архитектура

┌────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ Producers │ --> │ Ingest Layer │ --> │ Validation/AML │
└────────────────┘ └─────────────────┘ └─────────────────┘
│ │
v v
┌─────────────┐ ┌──────────────┐
│ Scheduler │ ---> │ Payout DAG │
└─────────────┘ └──────────────┘
│ │
v v
┌────────────────┐ ┌─────────────────┐
│ Queue/Outbox │ -----> │ Chain Drivers │
└────────────────┘ └─────────────────┘
│ │
v v
┌──────────────┐ ┌───────────────┐
│ Reconciler │ <----- │ Chain Indexers │
└──────────────┘ └───────────────┘
│
v
┌──────────────┐
│ Audit/BI │
└──────────────┘

markdown
Копировать код

Компоненты:
- Ingest Layer: CSV/JSON, API, gRPC. Валидация схемы, нормализация адресов, дедупликация получателей.
- Validation/AML: правила ABAC, velocity-лимиты, серые списки, внешние провайдеры KYC/KYB.
- Scheduler: формирование батчей по лимитам газа/комиссий, приоритетам и размерам окна.
- Payout DAG: оркестрация шагов кампании, ретраи, backoff, circuit-breaker.
- Queue/Outbox: надежная доставка в драйверы, гарантированная запись перед отправкой (Transactional Outbox).
- Chain Drivers: абстракции разных сетей с единым контрактом, подписи в HSM/внешнем валте.
- Reconciler: ончейн-подтверждения, сверка статусов, компensaции при частичном успехе.
- Audit/BI: неизменяемый журнал событий, выгрузки в DWH.

## Модель данных (RDBMS)

Таблицы (миграции предоставляются в директории `migrations/` проекта-реализации):

- `campaigns`:
  - `id` UUID PK
  - `name` text
  - `status` enum(pending, running, paused, completed, canceled, failed)
  - `chain` text
  - `token_contract` text nullable
  - `start_at`, `end_at` timestamptz
  - `created_by` text
  - индексы: `(status)`, `(chain, status)`

- `recipients`:
  - `id` UUID PK
  - `campaign_id` UUID FK
  - `address` text
  - `amount` numeric(78,0) или decimal в минимальных единицах
  - `metadata` jsonb
  - уникальный индекс `(campaign_id, address)`

- `payouts`:
  - `id` UUID PK
  - `campaign_id` UUID FK
  - `recipient_id` UUID FK
  - `payout_id` text unique (идемпотентность)
  - `status` enum(queued, submitted, confirmed, failed, compensated)
  - `tx_hash` text unique nullable
  - `error_code`, `error_msg` text
  - индексы: `(campaign_id, status)`, `(tx_hash)`

- `rate_limits`:
  - `key` text PK
  - `quota`, `window_sec` int
  - `used`, `reset_at`

- `audit_log` (append-only):
  - `ts` timestamptz
  - `actor` text
  - `action` text
  - `entity` text
  - `entity_id` text
  - `details` jsonb

## Идемпотентность

- Внешним системам требуется передавать стабильный `payout_id`.
- На уровне БД — уникальный индекс `payouts.payout_id`.
- Повторная отправка при сетевых/узловых сбоях безопасна: запись переиспользуется, драйвер проверяет существующий `tx_hash`.
- On-chain подтверждение фиксирует финальный статус и блокирует повторные выплаты.

## Антифрод, лимиты, комплаенс

- Allow/Deny-листы на уровне кампании и глобально.
- Velocity-лимит на адрес/домен/ASN: конфигурируемые окна и квоты.
- Гео-ограничения и санкционные списки через внешний провайдер.
- Контроль dust-сумм, минимальных и максимальных гранулярностей.
- Canary-выплаты: 1-5 адресов для раннего детекта аномалий.
- Shadow-режим: полный проход без ончейн-подписок, сбор метрик и готовность к запуску.

## Конфигурация

Переменные окружения:

AM_DB_DSN=postgresql+psycopg2://user:pass@host:5432/airdrop
AM_QUEUE_URL=redis://localhost:6379/0
AM_OUTBOX_TOPIC=airdrop.outbox
AM_HSM_URI=pkcs11:token=Prod;slot=0
AM_CHAIN_DRIVERS=evm,ton,solana
AM_PROMETHEUS=1
AM_PROM_PORT=9108
AM_JSONL_PATH=/var/log/airdrop/events.jsonl
AM_MAX_BATCH_SIZE=500
AM_MAX_CONCURRENCY=8
AM_RATE_LIMIT_GLOBAL=300:60

markdown
Копировать код

Секреты и ключи не хранятся в конфиге, а берутся из внешнего валта/HSM.

## API

gRPC/HTTP контуры (описания protobuf/OpenAPI входят в основной репозиторий реализации):

- `POST /api/v1/campaigns` — создать кампанию.
- `POST /api/v1/campaigns/{id}/recipients:ingest` — загрузить получателей (CSV/JSON).
- `POST /api/v1/campaigns/{id}:start|pause|resume|cancel`
- `GET /api/v1/payouts/{payout_id}` — статус выплаты.
- `GET /api/v1/campaigns/{id}/metrics` — метрики кампании.

События Audit в JSONL и в брокере событий:
- `campaign.created`, `campaign.started`, `payout.submitted`, `payout.confirmed`, `payout.failed`, `reconcile.completed`.

## CLI

airdrop
--dsn $AM_DB_DSN
campaigns create --name Q4-Rewards --chain evm --token 0xToken

airdrop recipients ingest --campaign Q4-Rewards --file recipients.csv

airdrop run --campaign Q4-Rewards --dry-run
airdrop run --campaign Q4-Rewards --max-batch 200 --concurrency 8

airdrop payouts status --payout-id abc123
airdrop reconcile --campaign Q4-Rewards --from-block 21000000

shell
Копировать код

CLI обеспечивает идемпотентные операции и безопасные ретраи.

## Драйверы сетей

Единый интерфейс драйвера:

SubmitResult submit_transfer(Recipient r, Amount a, Options o)
ConfirmResult confirm_tx(Hash h)
EstimateResult estimate_fees(Batch b)

markdown
Копировать код

Реализации:
- `evm`: Web3 provider, EIP-1559, nonce-manager, gas-cap, мульти-сиг.
- `ton`: high-level клиент, управления seqno, workchain, jetton-трансферы.
- `solana`: транзакции с приорити-фис, композитор инструкций.

Подпись транзакций — только через HSM/внешний валт. В оффлайне драйвер возвращает готовые unsigned tx для последующей подписи.

## Наблюдаемость

- Prometheus: счетчики `airdrop_payouts_total`, `airdrop_errors_total`, гистограммы `airdrop_latency_seconds`, gauge-метрики для очередей.
- OpenTelemetry трассировка для критических путей, связывание `payout_id` с `trace_id`.
- JSONL-события для офлайн-аудита в `AM_JSONL_PATH`.
- Дашборды: SLA по подтверждениям, процент ошибок по драйверам, аномалии.

## Надежность и отказоустойчивость

- Transactional Outbox для гарантированной доставки.
- Ретраи с экспоненциальным backoff и jitter.
- Circuit-breaker на уровне драйверов.
- Компенсации: переход в `compensated` при частично выполненных батчах.
- Снапшоты кампаний и checkpoint-маркеры.

## Безопасность

- Разделение ролей: Initiator, Approver, Signer, Operator.
- MFA и временные токены доступа.
- HSM/внешний валт для закрытых ключей, ротация, ограничение доменов использования.
- Политики RBAC/ABAC на API и CLI.
- Политики секретов и Zero-Trust сетевые правила.

## Тестирование

- Юнит-тесты: симуляторы драйверов сетей, проверки идемпотентности.
- Интеграционные тесты: ephemeral-сети, canary-скрипты.
- Нагрузочные: эмуляция больших CSV, окно лимитов, деградация узлов.
- Security-тесты: негативные кейсы, reorg-сценарии, двойная отправка.

## Миграции и развертывание

- Миграции БД с версионированием.
- Контейнеризация: Docker-образы, healthchecks, readiness-пробы.
- CI/CD: линтеры, SAST/DAST, подписание артефактов, SBOM.
- Развертывание: Helm-чарты, горизонтальное масштабирование воркеров.

## Ограничения

- Ложноположительные срабатывания антифрода требуют тюнинга правил.
- Разные сети имеют разные финалити и комиссии; стратегия батчинга должна учитывать специфику.

## Лицензия

Apache-2.0. См. файл LICENSE.