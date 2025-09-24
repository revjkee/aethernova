-- 0003_indices.sql — Производственные индексы для ledger-core
-- Target: PostgreSQL >= 13
-- ВАЖНО: миграция нетранзакционная из‑за CREATE INDEX CONCURRENTLY.
-- Убедитесь, что ваш миграционный инструмент НЕ оборачивает файл в BEGIN/COMMIT.

-- Общие безопасные лимиты блокировок
SET lock_timeout = '5s';
SET statement_timeout = '0';
SET idle_in_transaction_session_timeout = '0';
SET client_min_messages = warning;

-- Настраиваем путь поиска (кастомизируйте при необходимости)
-- Предполагается схема ledger
SET search_path = ledger, public;

--------------------------------------------------------------------------------
-- ТАБЛИЦА: accounts
-- Частые запросы: поиск по account_number, customer_id, активные аккаунты.
--------------------------------------------------------------------------------

-- Уникальность номера счёта
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS ux_accounts_account_number
  ON accounts (account_number);

-- Поиск аккаунтов пользователя
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_accounts_customer
  ON accounts (customer_id);

-- Частичный индекс по активным аккаунтам
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_accounts_customer_active
  ON accounts (customer_id)
  WHERE status = 'active';

--------------------------------------------------------------------------------
-- ТАБЛИЦА: transactions
-- Частые запросы: лента транзакций по аккаунту/времени, статусные очереди,
-- поиск по идемпотентному ключу и метаданным.
--------------------------------------------------------------------------------

-- Покрывающий индекс для ленты транзакций аккаунта
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_tx_account_created_at
  ON transactions (account_id, created_at DESC)
  INCLUDE (amount, currency, status);

-- Очередь "в работе": частичный индекс по pending/initiated
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_tx_pending_account_created_at
  ON transactions (account_id, created_at DESC)
  WHERE status IN ('pending','initiated');

-- Быстрый поиск по идемпотентному ключу
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS ux_tx_idempotency_key
  ON transactions (idempotency_key);

-- Поиск по внешнему tx_id (например, on‑chain/платёжная система)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_tx_external_tx_id
  ON transactions (tx_id);

-- GIN по метаданным JSONB: ускоряет queries вида metadata @> {...}
CREATE INDEX CONCURRENTLY IF NOT EXISTS gin_tx_metadata
  ON transactions
  USING GIN (metadata jsonb_path_ops);

-- Индекс под FK на партионный/батч‑идентификатор (если присутствует)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_tx_batch_id
  ON transactions (batch_id);

--------------------------------------------------------------------------------
-- ТАБЛИЦА: ledger_entries
-- Частые запросы: выписка по аккаунту/диапазону дат, агрегации по суммам.
-- Большие объёмы данных — полезен BRIN по времени.
--------------------------------------------------------------------------------

-- Композитный покрывающий индекс по аккаунту и дате бронирования
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_le_account_booking
  ON ledger_entries (account_id, booking_date DESC, seq ASC)
  INCLUDE (amount, currency, tx_id);

-- BRIN для ускорения сканирований по времени на больших таблицах
CREATE INDEX CONCURRENTLY IF NOT EXISTS brin_le_created_at
  ON ledger_entries
  USING BRIN (created_at) WITH (pages_per_range = 32);

-- Быстрый переход от проводки к транзакции
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_le_tx_id
  ON ledger_entries (tx_id);

--------------------------------------------------------------------------------
-- ТАБЛИЦА: payouts (если используется модуль выплат)
-- Частые запросы: статусы, дата создания, связь с транзакцией.
--------------------------------------------------------------------------------

-- Очередь выплат по статусу (частичный)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_payouts_pending_created
  ON payouts (created_at DESC)
  WHERE status IN ('queued','pending');

-- Поиск выплат по транзакции
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_payouts_tx
  ON payouts (transaction_id);

--------------------------------------------------------------------------------
-- ТАБЛИЦА: audit_log (большой объём, только добавление)
-- Типовые запросы: диапазоны по времени и поиск по JSONB контексту.
--------------------------------------------------------------------------------

-- BRIN по времени для дешёвых time‑range сканов
CREATE INDEX CONCURRENTLY IF NOT EXISTS brin_audit_ts
  ON audit_log
  USING BRIN (ts) WITH (pages_per_range = 64);

-- GIN по контексту (jsonb) для поиска по ключам/значениям
CREATE INDEX CONCURRENTLY IF NOT EXISTS gin_audit_context
  ON audit_log
  USING GIN (context jsonb_path_ops);

--------------------------------------------------------------------------------
-- ДОПОЛНИТЕЛЬНО: триграммы для поиска по частичным строкам (если pg_trgm установлен)
-- Применимо к колонкам вроде reference, external_id.
--------------------------------------------------------------------------------

-- CREATE EXTENSION IF NOT EXISTS pg_trgm; -- выполнить отдельно при необходимости
-- CREATE INDEX CONCURRENTLY IF NOT EXISTS gin_tx_reference_trgm
--   ON transactions USING GIN (reference gin_trgm_ops);

--------------------------------------------------------------------------------
-- АНАЛИЗ ВЫБОРОК (опционально; безопасно, но может занять время на больших таблицах)
--------------------------------------------------------------------------------

-- ANALYZE VERBOSE accounts;
-- ANALYZE VERBOSE transactions;
-- ANALYZE VERBOSE ledger_entries;
-- ANALYZE VERBOSE payouts;
-- ANALYZE VERBOSE audit_log;
