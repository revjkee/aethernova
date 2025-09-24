-- 0001_init.sql — Ledger Core bootstrap
-- Требования: PostgreSQL 14+ (из-за GENERATED, партиционирования и RLS)
-- Идempotent: да (CREATE IF NOT EXISTS, осторожно с ENUM/DOMAIN)

BEGIN;

-- =========================
-- Расширения
-- =========================
CREATE EXTENSION IF NOT EXISTS pgcrypto;     -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS btree_gist;   -- индексы/исключающие ограничения
CREATE EXTENSION IF NOT EXISTS citext;       -- case-insensitive уникальность (имена журналов/счетов при желании)

-- =========================
-- Схема и роли
-- =========================
CREATE SCHEMA IF NOT EXISTS ledger AUTHORIZATION CURRENT_USER;

-- Рекомендуемые параметры приложения (используются в политиках RLS)
-- SELECT set_config('app.current_journal_id', '<uuid>', true);

-- =========================
-- Типы и домены
-- =========================
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'tx_status' AND typnamespace = 'ledger'::regnamespace) THEN
    CREATE TYPE ledger.tx_status AS ENUM ('DRAFT','PENDING','POSTED','FAILED','REVERSED');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'side' AND typnamespace = 'ledger'::regnamespace) THEN
    CREATE TYPE ledger.side AS ENUM ('DEBIT','CREDIT');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'account_type' AND typnamespace = 'ledger'::regnamespace) THEN
    CREATE TYPE ledger.account_type AS ENUM ('ASSET','LIABILITY','EQUITY','INCOME','EXPENSE','OFFBALANCE');
  END IF;
END$$;

-- Домены для строгих значений
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'currency_code' AND typnamespace = 'ledger'::regnamespace) THEN
    EXECUTE $D$
      CREATE DOMAIN ledger.currency_code AS text
        CHECK (length(VALUE) BETWEEN 3 AND 32 AND VALUE ~ '^[A-Z0-9:_\-.]+$');
    $D$;
  END IF;
END$$;

-- =========================
-- Таблицы справочников
-- =========================

-- Журналы (книги)
CREATE TABLE IF NOT EXISTS ledger.journals (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name         citext NOT NULL UNIQUE,
  description  text,
  created_at   timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE ledger.journals IS 'Журналы (книги) учёта';

-- План счетов (по журналу)
CREATE TABLE IF NOT EXISTS ledger.accounts (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  journal_id   uuid NOT NULL REFERENCES ledger.journals(id) ON DELETE CASCADE,
  code         text NOT NULL,
  name         text NOT NULL,
  type         ledger.account_type NOT NULL,
  parent_id    uuid NULL REFERENCES ledger.accounts(id) ON DELETE RESTRICT,
  currency     ledger.currency_code NULL,         -- если счёт валютно-специфический
  metadata     jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (journal_id, code)
);
COMMENT ON TABLE ledger.accounts IS 'Счета учёта (Chart of Accounts) в рамках журнала';
CREATE INDEX IF NOT EXISTS idx_accounts_journal_type ON ledger.accounts (journal_id, type);
CREATE INDEX IF NOT EXISTS idx_accounts_parent ON ledger.accounts (parent_id);
CREATE INDEX IF NOT EXISTS idx_accounts_metadata_gin ON ledger.accounts USING GIN (metadata jsonb_path_ops);

-- =========================
-- Транзакции и проводки
-- =========================

-- Транзакции
CREATE TABLE IF NOT EXISTS ledger.transactions (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  journal_id       uuid NOT NULL REFERENCES ledger.journals(id) ON DELETE CASCADE,
  status           ledger.tx_status NOT NULL DEFAULT 'DRAFT',
  reference        text NULL,
  description      text NULL,
  labels           jsonb NOT NULL DEFAULT '{}'::jsonb,
  attributes       jsonb NOT NULL DEFAULT '{}'::jsonb,
  idempotency_key  text NULL,
  reversed_of      uuid NULL REFERENCES ledger.transactions(id) ON DELETE RESTRICT,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  posted_at        timestamptz NULL,
  version          bigint NOT NULL DEFAULT 1,                 -- optimistic lock
  etag             text GENERATED ALWAYS AS (
                     encode(digest(
                       coalesce(reference,'') || '|' ||
                       coalesce(description,'') || '|' ||
                       status::text || '|' ||
                       coalesce(idempotency_key,'') || '|' ||
                       coalesce(posted_at::text,'') || '|' ||
                       version::text, 'sha256'), 'hex')
                   ) STORED
);
COMMENT ON TABLE ledger.transactions IS 'Транзакции двойной записи в рамках журнала';

-- Уникальность идемпотентности в рамках журнала (не для NULL)
CREATE UNIQUE INDEX IF NOT EXISTS uq_tx_journal_idem
ON ledger.transactions (journal_id, idempotency_key)
WHERE idempotency_key IS NOT NULL;

-- Индексы для выборок
CREATE INDEX IF NOT EXISTS idx_tx_journal_status_created ON ledger.transactions (journal_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_tx_posted ON ledger.transactions (posted_at)
  WHERE status = 'POSTED';
CREATE INDEX IF NOT EXISTS idx_tx_labels_gin ON ledger.transactions USING GIN (labels jsonb_path_ops);
CREATE INDEX IF NOT EXISTS idx_tx_attributes_gin ON ledger.transactions USING GIN (attributes jsonb_path_ops);

-- Проводки (партиционируемы по effective_at)
CREATE TABLE IF NOT EXISTS ledger.entries (
  id             bigserial PRIMARY KEY,
  transaction_id uuid NOT NULL REFERENCES ledger.transactions(id) ON DELETE CASCADE,
  account_id     uuid NOT NULL REFERENCES ledger.accounts(id) ON DELETE RESTRICT,
  side           ledger.side NOT NULL,
  currency       ledger.currency_code NOT NULL,
  amount         numeric(38,18) NOT NULL CHECK (amount > 0),
  memo           text NULL,
  attributes     jsonb NOT NULL DEFAULT '{}'::jsonb,
  subledger      text NULL,
  effective_at   timestamptz NOT NULL,              -- дата проводки для партиционирования/отчётности
  created_at     timestamptz NOT NULL DEFAULT now()
) PARTITION BY RANGE (effective_at);

COMMENT ON TABLE ledger.entries IS 'Проводки (entries) транзакций; партиционирование по effective_at';

-- Партиция по умолчанию (safety net)
CREATE TABLE IF NOT EXISTS ledger.entries_default
  PARTITION OF ledger.entries DEFAULT;

-- Рекомендуемые партиции (шаблон: ежемесячно). Реальное создание обычно автоматизируется отдельной миграцией/джобом.
-- Ниже создаём две партиции как пример и опору для планов, даты замените согласно политике.
DO $$
DECLARE
  y int := date_part('year', now())::int;
BEGIN
  EXECUTE format($f$
    CREATE TABLE IF NOT EXISTS ledger.entries_y%1$s_m01 PARTITION OF ledger.entries
      FOR VALUES FROM (%2$L) TO (%3$L);
  $f$, y, to_timestamp((y || '-01-01')::text,'YYYY-MM-DD'), to_timestamp((y || '-02-01')::text,'YYYY-MM-DD'));

  EXECUTE format($f$
    CREATE TABLE IF NOT EXISTS ledger.entries_y%1$s_m02 PARTITION OF ledger.entries
      FOR VALUES FROM (%2$L) TO (%3$L);
  $f$, y, to_timestamp((y || '-02-01')::text,'YYYY-MM-DD'), to_timestamp((y || '-03-01')::text,'YYYY-MM-DD'));
END $$;

-- Индексы по проводкам
CREATE INDEX IF NOT EXISTS idx_entries_tx ON ledger.entries (transaction_id);
CREATE INDEX IF NOT EXISTS idx_entries_account_time ON ledger.entries (account_id, effective_at DESC);
CREATE INDEX IF NOT EXISTS idx_entries_currency ON ledger.entries (currency);
CREATE INDEX IF NOT EXISTS idx_entries_side_account ON ledger.entries (side, account_id);
CREATE INDEX IF NOT EXISTS idx_entries_attributes_gin ON ledger.entries USING GIN (attributes jsonb_path_ops);

-- =========================
-- Outbox для CDC/интеграций
-- =========================
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'outbox_status' AND typnamespace = 'ledger'::regnamespace) THEN
    CREATE TYPE ledger.outbox_status AS ENUM ('PENDING','PUBLISHED','FAILED');
  END IF;
END$$;

CREATE TABLE IF NOT EXISTS ledger.outbox_events (
  id             bigserial PRIMARY KEY,
  event_key      uuid NOT NULL DEFAULT gen_random_uuid(),         -- для дедупликации
  tx_id          uuid NULL REFERENCES ledger.transactions(id) ON DELETE SET NULL,
  topic          text NOT NULL,
  payload        jsonb NOT NULL,
  status         ledger.outbox_status NOT NULL DEFAULT 'PENDING',
  error          text NULL,
  retry_count    int NOT NULL DEFAULT 0,
  created_at     timestamptz NOT NULL DEFAULT now(),
  published_at   timestamptz NULL,
  UNIQUE (event_key)
);
CREATE INDEX IF NOT EXISTS idx_outbox_status_created ON ledger.outbox_events (status, created_at);
CREATE INDEX IF NOT EXISTS idx_outbox_topic ON ledger.outbox_events (topic);

-- =========================
-- Функции и триггеры
-- =========================

-- updated_at/version bump для transactions
CREATE OR REPLACE FUNCTION ledger.fn_tx_touch() RETURNS trigger AS $$
BEGIN
  NEW.updated_at := now();
  IF TG_OP IN ('UPDATE') THEN
    NEW.version := COALESCE(OLD.version, 1) + 1;
  END IF;

  -- Постинг: posted_at обязателен и переносится на проводки как effective_at при необходимости
  IF NEW.status = 'POSTED' AND NEW.posted_at IS NULL THEN
    NEW.posted_at := now();
  END IF;

  RETURN NEW;
END$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_tx_touch ON ledger.transactions;
CREATE TRIGGER trg_tx_touch
BEFORE INSERT OR UPDATE ON ledger.transactions
FOR EACH ROW
EXECUTE FUNCTION ledger.fn_tx_touch();

-- При смене статуса на POSTED синхронизировать effective_at для проводок (однократно)
CREATE OR REPLACE FUNCTION ledger.fn_tx_sync_entries_posted() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'UPDATE'
     AND OLD.status IS DISTINCT FROM NEW.status
     AND NEW.status = 'POSTED' THEN
    UPDATE ledger.entries e
    SET effective_at = COALESCE(NEW.posted_at, now())
    WHERE e.transaction_id = NEW.id
      AND e.effective_at IS DISTINCT FROM COALESCE(NEW.posted_at, now());
  END IF;
  RETURN NULL;
END$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_tx_sync_entries_posted ON ledger.transactions;
CREATE TRIGGER trg_tx_sync_entries_posted
AFTER UPDATE ON ledger.transactions
FOR EACH ROW
EXECUTE FUNCTION ledger.fn_tx_sync_entries_posted();

-- Проверка инварианта двойной записи по каждой валюте (деферрируемая)
CREATE OR REPLACE FUNCTION ledger.fn_enforce_double_entry() RETURNS trigger AS $$
DECLARE
  v_tx uuid := COALESCE(NEW.transaction_id, OLD.transaction_id);
  v_unbalanced_count int;
BEGIN
  -- Пустая транзакция запрещена
  IF NOT EXISTS (SELECT 1 FROM ledger.entries WHERE transaction_id = v_tx) THEN
    RAISE EXCEPTION 'Transaction % has no entries', v_tx USING ERRCODE = '23514'; -- check_violation
  END IF;

  -- Сумма дебетов = сумма кредитов по каждой валюте
  SELECT count(*) INTO v_unbalanced_count
  FROM (
    SELECT currency,
           SUM(CASE side WHEN 'DEBIT' THEN amount ELSE -amount END) AS net
    FROM ledger.entries
    WHERE transaction_id = v_tx
    GROUP BY currency
  ) s
  WHERE s.net <> 0;

  IF v_unbalanced_count > 0 THEN
    RAISE EXCEPTION 'Transaction % is not balanced per currency', v_tx USING ERRCODE = '23514';
  END IF;

  RETURN NULL;
END$$ LANGUAGE plpgsql;

-- Деферрируемый constraint-триггер на entries (сработает в момент COMMIT)
DROP TRIGGER IF EXISTS ctrg_entries_double_entry ON ledger.entries;
CREATE CONSTRAINT TRIGGER ctrg_entries_double_entry
AFTER INSERT OR UPDATE OR DELETE ON ledger.entries
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION ledger.fn_enforce_double_entry();

-- Бизнес-правила для REVERSED
CREATE OR REPLACE FUNCTION ledger.fn_tx_reversed_guard() RETURNS trigger AS $$
DECLARE v_status ledger.tx_status;
BEGIN
  IF NEW.reversed_of IS NOT NULL THEN
    IF NEW.status <> 'REVERSED' THEN
      RAISE EXCEPTION 'reversed_of can be set only when status=REVERSED' USING ERRCODE='23514';
    END IF;
    SELECT status INTO v_status FROM ledger.transactions WHERE id = NEW.reversed_of;
    IF v_status IS DISTINCT FROM 'POSTED' THEN
      RAISE EXCEPTION 'Only POSTED transactions can be reversed' USING ERRCODE='23514';
    END IF;
  END IF;
  RETURN NEW;
END$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_tx_reversed_guard ON ledger.transactions;
CREATE TRIGGER trg_tx_reversed_guard
BEFORE INSERT OR UPDATE ON ledger.transactions
FOR EACH ROW
EXECUTE FUNCTION ledger.fn_tx_reversed_guard();

-- =========================
-- Политики безопасности (RLS)
-- =========================

-- Включаем RLS для таблиц с данными
ALTER TABLE ledger.transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger.accounts ENABLE ROW LEVEL SECURITY;

-- Политика: доступ только к данным своего журнала по параметру app.current_journal_id (uuid)
-- Настройка параметра выполняется на уровне сессии приложения.
CREATE POLICY IF NOT EXISTS p_tx_by_journal
ON ledger.transactions
USING (journal_id::text = current_setting('app.current_journal_id', true));

CREATE POLICY IF NOT EXISTS p_entries_by_journal
ON ledger.entries
USING (
  EXISTS (
    SELECT 1 FROM ledger.transactions t
    WHERE t.id = entries.transaction_id
      AND t.journal_id::text = current_setting('app.current_journal_id', true)
  )
);

CREATE POLICY IF NOT EXISTS p_accounts_by_journal
ON ledger.accounts
USING (journal_id::text = current_setting('app.current_journal_id', true));

-- =========================
-- Констрейнты целостности на связки журналов
-- =========================

-- Все проводки должны ссылаться на счёт из того же журнала, что и транзакция
CREATE OR REPLACE FUNCTION ledger.fn_entry_cross_journal_guard() RETURNS trigger AS $$
DECLARE
  v_tx_journal uuid;
  v_acc_journal uuid;
BEGIN
  SELECT journal_id INTO v_tx_journal FROM ledger.transactions WHERE id = NEW.transaction_id;
  SELECT journal_id INTO v_acc_journal FROM ledger.accounts     WHERE id = NEW.account_id;

  IF v_tx_journal IS DISTINCT FROM v_acc_journal THEN
    RAISE EXCEPTION 'Entry journal mismatch: tx % vs account %', v_tx_journal, v_acc_journal USING ERRCODE='23503';
  END IF;

  RETURN NEW;
END$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_entry_cross_journal_guard ON ledger.entries;
CREATE TRIGGER trg_entry_cross_journal_guard
BEFORE INSERT OR UPDATE ON ledger.entries
FOR EACH ROW
EXECUTE FUNCTION ledger.fn_entry_cross_journal_guard();

-- =========================
-- Представления для агрегатов (опционально, ускоряют частые запросы)
-- =========================

CREATE OR REPLACE VIEW ledger.v_tx_totals AS
SELECT
  e.transaction_id AS id,
  e.currency,
  SUM(CASE e.side WHEN 'DEBIT' THEN e.amount ELSE 0 END)  AS total_debits,
  SUM(CASE e.side WHEN 'CREDIT' THEN e.amount ELSE 0 END) AS total_credits
FROM ledger.entries e
GROUP BY e.transaction_id, e.currency;

-- =========================
-- Комментарии
-- =========================
COMMENT ON COLUMN ledger.entries.amount IS 'Положительная сумма, знак задаётся полем side';
COMMENT ON COLUMN ledger.entries.effective_at IS 'Дата эффекта проводки; при постинге синхронизируется с posted_at транзакции';

-- =========================
-- Финал
-- =========================
COMMIT;
